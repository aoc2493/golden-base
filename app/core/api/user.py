from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
from app.core.database import get_db
from app.core.models import (
    User, Order, Report, Feedback, ResultCache,
    UserMembership, UserEntitlement, Distributor, Withdrawal, Favorite,
)
from app.core.schemas import (UserUpdateRequest,
                         ConsentSignRequest, ConsentWithdrawRequest)
from app.core.auth import (get_current_user, add_to_blacklist, add_user_to_blacklist,
                      decode_jwt_token, clear_auth_cookie, redis_client)
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from app.core.api.common import (success, error, ErrorCode, get_client_ip, redis_rate_limit)
from app.config import settings
from app.plugins import registry
from app.core.services import consent as consent_svc
from app.core.services import minor_guard as guard_svc
from app.core.services import distribution_compliance as compliance_svc
from datetime import datetime, timezone
from decimal import Decimal
import logging
import secrets

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/user", tags=["用户"])
security = HTTPBearer(auto_error=False)

# users 表四个身份标识列（device_code / oa_openid / mp_openid / unionid）均为 String(64) 且带唯一约束
_IDENT_MAX_LEN = 64


def _archive_ident(value: str, suffix: str) -> str:
    """注销时归档身份标识以释放唯一约束，并保证结果不超列长。
    原实现直接拼接归档后缀：LoginRequest.code 允许 64 字符，拼上 23 字符后缀就到 87，
    MySQL 下报 1406 Data too long，整个注销事务失败（用户永远无法注销）；
    SQLite 不校验长度会静默写入超长值，直到迁库时才集中爆发。
    超长时截断前缀、保留尾部时间戳+随机段，既守住列长又维持唯一性。"""
    if not value:
        return value
    if len(value) + len(suffix) <= _IDENT_MAX_LEN:
        return f"{value}{suffix}"
    keep = _IDENT_MAX_LEN - len(suffix)
    return f"{value[:max(keep, 0)]}{suffix}"


@router.get("/info")
async def get_user_info(db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    return success({"nickname": user.nickname, "avatar_url": user.avatar_url, "id": user.id})


def _allowed_avatar_url(url: str) -> bool:
    """头像 URL 白名单：只接受「站内相对路径」与「已配置的对象存储域名」。

    【安全审计修复】原实现把前端传入的任意字符串直接落库：可填 javascript:/data: URI
    （前端一旦用 href/innerHTML 渲染即为存储型 XSS）、任意外站地址（追踪像素、钓鱼图、
    盗链），也让「头像」变成可被引用的任意 URL 字段。头像只可能来自两条链路——
    /upload/avatar 与微信头像拉取，两者产出的 URL 形态只有下面两类，故可白名单化。
    """
    u = (url or "").strip()
    if not u:
        return True                      # 允许清空头像
    if u.startswith("//") or "\\" in u:
        return False                     # 协议相对外站 / 反斜线变形
    if "://" not in u:
        # 站内相对路径：必须是站内的单斜线绝对路径，禁止目录穿越
        return u.startswith("/") and ".." not in u
    from urllib.parse import urlparse
    p = urlparse(u)
    if p.scheme not in ("http", "https"):
        return False                     # javascript:/data:/file: 一律拒绝
    host = (p.hostname or "").lower()
    allowed = {
        (settings.COS_CDN_DOMAIN or "").split("://")[-1].split("/")[0].lower(),
        f"{settings.COS_BUCKET}.cos.{settings.COS_REGION}.myqcloud.com".lower(),
    }
    allowed.discard("")
    return bool(host) and (host in allowed or any(host.endswith("." + a) for a in allowed))


@router.put("/info")
async def update_user_info(req: UserUpdateRequest, db: AsyncSession = Depends(get_db),
                           user: User = Depends(get_current_user)):
    warned = False
    if req.nickname is not None:
        nickname = req.nickname.strip()[:50]
        # M3③（第五十七/五十八条）：昵称是对他人可见的 UGC，落库前过敏感词。
        # 一级拦截词 blocked → 拒绝改名（CONTENT_VIOLATION）；二级预警词 warned → 放行但回文字提示。
        sw = await compliance_svc.check_sensitive(db, nickname)
        if sw["blocked"]:
            return error(ErrorCode.CONTENT_VIOLATION, "昵称含违规内容，请修改后再试")
        warned = bool(sw.get("warned"))
        user.nickname = nickname
    if req.avatar_url is not None:
        if not _allowed_avatar_url(req.avatar_url):
            return error(ErrorCode.PARAM_ERROR, "头像地址不合法，请通过上传功能设置头像")
        user.avatar_url = req.avatar_url.strip()
    await db.flush()
    return success({"nickname": user.nickname, "avatar_url": user.avatar_url},
                   msg="昵称含疑似违规内容，请注意规范用词" if warned else "success")


# ==================== A6：隐私授权管理（个保法第十五条：便捷的撤回同意方式） ====================
@router.get("/consents")
async def list_consents(db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    """我的授权清单：每项授权的当前状态、用途、能否撤回与撤回后果。
    文案由后端下发（services/consent.CONSENT_ITEMS），不在前端另写一份。"""
    return success(await consent_svc.get_overview(db, user))


async def _consent_write_guard(request: Request, user: User):
    """合规留痕写入口限流。放行返回 None，否则返回已构造好的限流响应。

    与 /api/feedback 同一理由（那里已修）：每次提交都是一条 INSERT。不同之处在于
    compliance_consents 的行是法定证据，保存≥3 年且任何路径都不会删除（含注销：
    注销只置空 users 表的个人信息，留痕行必须保留以证明平台履行过义务）。
    因此刷满它造成的不是「可清理的垃圾数据」，而是永久污染的证据表：
    事后要回答「这位用户到底何时同意过什么」时，得先从几万条重复行里辨认。
    按用户+IP 双维度计数，与 feedback 同口径（单维度都可被多账号/换 IP 绕过）。"""
    ip = get_client_ip(request)
    allowed = await redis_rate_limit(
        redis_client, f"rate:consent:{user.id}:{ip}", settings.RATE_LIMIT_CONSENT_PER_MIN, 60)
    if not allowed:
        return error(ErrorCode.RATE_LIMIT, "操作过于频繁，请稍后再试")
    return None


@router.post("/consent")
async def sign_consent(req: ConsentSignRequest, request: Request,
                       db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    """记录一次同意/勾选留痕（含撤回后的重新同意）。
    IP/设备/时间戳一律服务端补齐：留痕是发生争议时的证据，不能交给客户端自述。"""
    limited = await _consent_write_guard(request, user)
    if limited:
        return limited
    # P2 修复（证据表防伪造）：
    # ① doc_version 不采信客户端自报——伪造高版本号会污染 latest_agreed_version 的
    #    版本比对语义（留痕表按版本号判定生效状态），一律服务端写入当前生效版本；
    # ② order_id 必须归属当前用户，防止把同意留痕挂到他人订单上破坏证据链。
    doc_version = guard_svc.GUARD_VERSION
    order_id = req.order_id
    if order_id is not None:
        o = (await db.execute(select(Order).where(Order.id == order_id))).scalar_one_or_none()
        if o is None or o.user_id != user.id:
            return error(ErrorCode.PARAM_ERROR, "订单不存在或无权关联")
    ok, res = await consent_svc.sign(db, user, req.doc_type, doc_version=doc_version,
                                     agreed=req.agreed, order_id=order_id,
                                     ip=get_client_ip(request),
                                     user_agent=request.headers.get("user-agent"),
                                     reaffirm=bool(req.reaffirm))
    if not ok:
        return error(ErrorCode.PARAM_ERROR, str(res))
    # note 用于把「同意已记录、但推广链接因违规处置未恢复」这类部分生效的结果如实告知用户：
    # 点了按钮却没任何反馈，用户会以为系统坏了并反复重试。
    note = (res or {}).get("note") if isinstance(res, dict) else None
    return success({"doc_type": req.doc_type, "agreed": bool(req.agreed)}, msg=note or "已记录")


@router.post("/consent/withdraw")
async def withdraw_consent(req: ConsentWithdrawRequest, request: Request,
                           db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    """撤回同意。返回体带 effect（撤回后到底停什么），前端必须原样弹给用户：
    撤回是个有后果的动作，用户得先知道后果才能确认自己真的想撤。"""
    limited = await _consent_write_guard(request, user)
    if limited:
        return limited
    ok, msg = await consent_svc.withdraw(db, user, req.doc_type,
                                         ip=get_client_ip(request),
                                         user_agent=request.headers.get("user-agent"))
    if not ok:
        return error(ErrorCode.PARAM_ERROR, msg)
    return success({"doc_type": req.doc_type, "agreed": False, "effect": msg}, msg="已撤回同意")


# ==================== A8：年龄门槛与未成年人保护 ====================
# 2026-09-11 平台属主决策：成年声明/他人出生信息告知两道门槛前后端一起关闭，
# /age-gate 与 /age-declaration 两个接口随之下架（前端已无任何调用点）；
# services/minor_guard.gate_payer / gate_bio 恒放行，下单/计算/建档链路不再拦截。


@router.delete("/account")
async def delete_account(credentials: HTTPAuthorizationCredentials = Depends(security),
                         db: AsyncSession = Depends(get_db),
                         user: User = Depends(get_current_user)):
    """注销账号：N5 推广员改冻结而非物理删除，保证佣金流水可对账/可冲回"""
    user_id = user.id
    dist = (await db.execute(select(Distributor).where(Distributor.user_id == user_id))).scalar_one_or_none()
    if dist:
        if Decimal(str(dist.available_commission or 0)) > 0 or Decimal(str(dist.pending_commission or 0)) > 0:
            return error(ErrorCode.NO_PERMISSION, "账户尚有未结算或可提现佣金，请先提现或联系客服")
        # 必须用 scalars().first()：withdrawals 在 (user_id, status) 上没有任何唯一约束，
        # 同一用户存在两笔 auditing 是可能的（apply_withdrawal 修复前的并发穿透就造成过
        # 这种脏数据）。scalar_one_or_none() 命中多行会抛 MultipleResultsFound，
        # 注销接口从此永久 500 —— 用户再也无法注销账号（与 L6 同一类缺陷）。
        wd = (await db.execute(select(Withdrawal).where(
            Withdrawal.user_id == user_id, Withdrawal.status == "auditing"))).scalars().first()
        if wd:
            return error(ErrorCode.NO_PERMISSION, "存在审核中的提现，请处理完成后再注销")
    # 清除隐私关联数据
    await db.execute(delete(Feedback).where(Feedback.user_id == user_id))
    await db.execute(delete(Report).where(Report.user_id == user_id))
    await db.execute(delete(UserEntitlement).where(UserEntitlement.user_id == user_id))
    await db.execute(delete(UserMembership).where(UserMembership.user_id == user_id))
    # 插件专属业务数据（如业务档案）由各插件钩子清理；core 通用表在上方自管
    await registry.erase_user_data(user, db)
    await db.execute(delete(Favorite).where(Favorite.user_id == user_id))
    await db.execute(delete(ResultCache).where(ResultCache.user_id == user_id))
    # 订单/退款为财务凭证不删除，仅清空出生信息隐私
    await db.execute(Order.__table__.update().where(Order.user_id == user_id)
                     .values(input_snapshot=None, result_ref_id=None, biz_data=None))
    # N5：推广员冻结（status=0）而非物理删除，保留佣金流水用于对账与退款冲回
    if dist:
        dist.status = 0
    # 身份标识归档，释放唯一约束
    # 后缀定为 _del_ + 14 位时间戳 + 4 位密码学随机十六进制 = 23 字符：
    # 前端设备码为 h5- + 32 hex = 35 字符，35+23=58 仍不超 String(64) 列长，
    # 正常路径不会触发截断；随机段用于截断发生时的唯一保底（仅靠秒级时间戳不够）。
    _suffix = f"_del_{datetime.now().strftime('%Y%m%d%H%M%S')}{secrets.token_hex(2)}"
    if user.device_code:
        user.device_code = _archive_ident(user.device_code, _suffix)
    if user.oa_openid:
        user.oa_openid = _archive_ident(user.oa_openid, _suffix)
    if user.mp_openid:
        user.mp_openid = _archive_ident(user.mp_openid, _suffix)
    if user.unionid:
        user.unionid = _archive_ident(user.unionid, _suffix)
    user.status = 2
    user.nickname = None
    user.avatar_url = None
    user.phone = None
    # 双向定位：「最近登录标识」属个人信息，注销时随其他个人信息一并置空。
    # user_identities 台账保留原标识（与订单/退款不删同一口径）：开票与财务凭证的
    # 法定留存要求下，历史订单快照 login_id_value 必须仍能反查到账号归属；
    # 订单上的快照列也不清（它和 order_no/amount 一样是财务凭证的一部分）。
    user.last_login_type = None
    user.last_login_value = None
    # A8：自报出生日期属个人信息，注销时随其他个人信息一并置空。
    # 「该账号曾在 T 时点完成过成年声明、文本版本为 V」这件事由 compliance_consents 留痕保留
    # （法定留痕不得删），监管要看的是平台履行了门槛义务，而不是那个具体日期。
    user.declared_birth_date = None
    user.age_declared_at = None
    # M1/N19：当前 token 拉黑 + 用户级全设备拉黑
    if credentials:
        try:
            payload = decode_jwt_token(credentials.credentials)
            jti = payload.get("jti")
            exp = payload.get("exp")
            remaining = 7 * 24 * 3600
            if exp:
                remaining = max(1, int(exp - datetime.now(timezone.utc).timestamp()))
            if jti:
                await add_to_blacklist(user_id, jti, remaining)
            await add_user_to_blacklist(user_id, remaining)
        except Exception:
            # 拉黑失败（如 Redis 不可用）不阻断注销本身，但绝不能静默：
            # 否则令牌在自然过期前仍有效，安全事件无从排查
            logger.warning("注销拉黑令牌失败 user_id=%s", user_id, exc_info=True)
    # M4：注销同时清除 httpOnly Cookie 会话
    resp = JSONResponse(content=success())
    clear_auth_cookie(resp)
    return resp
