"""
管理端接口（订单/会员/分销/提现/用户统一接入）
- 令牌失败限流锁定 + 可选 IP 白名单，防暴力破解
- 退款幂等检查，已退款/退款中订单拒绝重复退款
- 退款三态（成功/处理中/失败）
- 所有写操作记录 admin_operation_logs
- 敏感操作二次密码
"""
import json
import hmac
import logging
import time
from fastapi import APIRouter, Body, Depends, Header, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_, and_, not_, update
from datetime import datetime
from app.core.database import get_db, row_lock
from app.core.models import (
    Withdrawal, Distributor, CommissionLog, Order, User,
    UserMembership, UserEntitlement, Refund, AdminOperationLog,
    ExamQuestion, ReconciliationDiff, ComplianceAssessment,
    InvoiceRequest,
)
from app.core.schemas import (AdminAuditRequest, AdminRefundRequest, AdminMembershipRequest,
                         AdminViolationRequest, AdminUnfreezeRequest, AdminLinkRequest,
                         AdminReportHandleRequest, AdminExternalReviewRequest,
                         AdminSensitiveWordRequest, AdminExamQuestionRequest, AdminRankSettleRequest,
                         AdminReconcileResolveRequest, AdminReconcileRunRequest,
                         AdminCryptoBackfillRequest, AdminComplianceAssessmentRequest,
                         AdminAlertTestRequest, AdminInvoiceIssueRequest,
                         AdminInvoiceRejectRequest)
from app.core.api.common import (AdminAuthDenied, success, error, ErrorCode, get_client_ip,
                            redis_acquire_lock, redis_release_lock, redis_rate_limit)
from app.core.auth import redis_client
from app.core.services.distribution import audit_withdrawal
from app.core.services import identity as identity_svc
# 实名/收款信息在库里是密文。列表页一律脱敏（mask_*），只有提现详情（二次密码
# 门禁 + 操作日志）才用 decrypt_field(strict=True) 解出明文供人工打款。
from app.core.utils.crypto_field import (decrypt_field, mask_name, mask_account,
                                    encrypt_field, is_encrypted)
# 告警通道。后台需要两个能力——看通道到底通不通（status），以及主动验一次（test）。
# 不在这里重写一份发送逻辑：两处各发一份就会出现「后台测试能收到、真故障时收不到」
# 这类最难查的分叉（两边参数不一致，而测试通过会让人误以为通道没问题）。
from app.core.utils import alert as alert_svc
# 发票台账。序列化口径（brief/detail）、状态常量与开具写入都走 service，
# 不在这里另拼一份：用户端与后台对同一行数据给出两种说法，是台账类功能最典型的失控方式。
from app.core.services import invoice as invoice_svc
from app.core.services import distribution_violation as dv
from app.core.services import distribution_rank as dr
from app.core.services import distribution_compliance as dc
from app.core.services.membership import admin_grant_membership, get_member_status
from app.core.services.fulfillment import revoke_refunded_order
from app.core.services.refund_state import apply_channel_refund_status
from app.core.services.reconcile import reconcile_day, reconcile_recent
from app.core.utils.payment import (apply_refund, gen_refund_no, alipay, wechat_pay,
                                   has_real_payment, no_payment_reason, query_refund)
from app.config import settings
from app.core.services import credential as credential_svc

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/admin", tags=["管理端"])


# admin.py / admin_extra.py 全量接口无 Redis 限流：admin_card.py 有 _admin_rate_limit，
# 而 admin.py / admin_extra.py 数十个接口只靠 require_admin 的进程内错误锁定兜底——
# token 一旦泄露即可无限速拖库（用户/订单/权益全量导出）。router 级依赖统一加
# IP 维度限流：240 次/分钟（正常运营操作远低于此），Redis 故障时放行（与全站限流同降级口径）。
async def _admin_router_rate_limit(request: Request):
    allowed = await redis_rate_limit(
        redis_client, f"rate:adminall:{get_client_ip(request)}", 240, 60)
    if not allowed:
        # router 依赖里拿不到 error() 的 JSON 包装，用 429 + 标准体；
        # 管理前端 request() 对非 0 响应统一抛错提示，行为一致
        from fastapi import HTTPException
        raise HTTPException(status_code=429, detail="操作过于频繁，请稍后再试")


admin_router = APIRouter(prefix="/admin", tags=["管理端"],
                         dependencies=[Depends(_admin_router_rate_limit)])
# 保持外部引用名不变（main.py import admin.router）
router = admin_router


async def _log_operation(db, request, action, target_type=None, target_id=None, detail=None):
    """写管理操作审计日志"""
    try:
        db.add(AdminOperationLog(
            action=action, target_type=target_type, target_id=str(target_id) if target_id else None,
            detail=json.dumps(detail, ensure_ascii=False, default=str)[:2000] if detail else None,
            ip=get_client_ip(request)))
    except Exception as e:
        logger.error(f"审计日志写入失败: {e}")


# Redis 不可用时的进程内失败计数兜底。爆破锁定原先完全依赖 Redis，
# 而本项目 Redis 异常时一律「降级放行」，Redis 一挂（本机开发环境正是如此），
# 管理令牌就退化为可无限速暴力破解——读不到计数、也写不进计数，锁定永不触发。
# 这里维护一份带时间窗的内存计数，与 Redis 计数取较大值判定锁定：
# 单进程部署下等价于 Redis 效果；多 worker 下每个 worker 各自计数，仍远优于无限制。
_LOCAL_ADMIN_FAIL = {}
_LOCAL_ADMIN_FAIL_MAX = 4096    # 容量上限：伪造来源 IP 制造海量键也撑不爆内存


def _local_fail_count(ip: str) -> int:
    """读取内存失败计数，过期即清零"""
    rec = _LOCAL_ADMIN_FAIL.get(ip)
    if not rec:
        return 0
    cnt, expire_at = rec
    if time.time() >= expire_at:
        _LOCAL_ADMIN_FAIL.pop(ip, None)
        return 0
    return cnt


def _local_fail_incr(ip: str) -> int:
    """内存失败计数 +1 并刷新锁定窗口"""
    now = time.time()
    if len(_LOCAL_ADMIN_FAIL) >= _LOCAL_ADMIN_FAIL_MAX:
        for k in [k for k, v in _LOCAL_ADMIN_FAIL.items() if v[1] <= now]:
            _LOCAL_ADMIN_FAIL.pop(k, None)
        if len(_LOCAL_ADMIN_FAIL) >= _LOCAL_ADMIN_FAIL_MAX:
            # 仍超限时只淘汰「最早到期」的一批，不再整体 clear()：
            # 整体重置会把正在进行中的合法锁定一并抹掉，等于给爆破者发一张免罚券。
            # 按到期时间升序淘汰 1/8，既控住内存又保留最近的有效锁定。
            victims = sorted(_LOCAL_ADMIN_FAIL, key=lambda kk: _LOCAL_ADMIN_FAIL[kk][1])
            for k in victims[: max(1, _LOCAL_ADMIN_FAIL_MAX // 8)]:
                _LOCAL_ADMIN_FAIL.pop(k, None)
    cnt = _local_fail_count(ip) + 1
    _LOCAL_ADMIN_FAIL[ip] = (cnt, now + settings.RATE_LIMIT_ADMIN_LOCK_SECONDS)
    return cnt


async def require_admin(request: Request, db: AsyncSession = Depends(get_db),
                        x_admin_token: str = Header(default="")) -> bool:
    """令牌校验 + 失败计数锁定 + IP 白名单（锁定后真正拒绝请求，不再继续比对令牌）
    门禁审计：每次决策（拒绝/锁定/通过）落 admin_operation_logs，上线后可追溯暴力破解与异常登录。
    审计只记 IP/路径/原因/失败计数，绝不记令牌内容；写入失败不影响鉴权判定（fail-open on audit，
    _log_operation 内部已吞异常）。

    上线前检查：失败不再以“返回 False”表达（那会让路由体以 HTTP 200 + code=6001 返回，
    爆破在 nginx 日志/监控/WAF 上与正常访问无法区分），改为抛出 AdminAuthDenied，
    由 main.py 统一回 HTTP 401 + code=6001；放行/拒绝的判定条件本身未变。"""
    ip = get_client_ip(request)
    path = request.url.path
    # 加固：代码默认值/空令牌在任意环境都不可用，避免 demo/测试环境
    # 沿用人人可得的默认令牌上线（生产已由启动自检拦截，此处补齐非生产缺口）
    if not settings.ADMIN_TOKEN or settings.ADMIN_TOKEN == "change-me-admin-token":
        await _log_operation(db, request, "admin_auth_denied", target_type="auth",
                             detail={"reason": "default_token", "path": path})
        raise AdminAuthDenied()
    # IP 白名单（配置后仅白名单可访问管理接口）
    wl = settings.admin_ip_whitelist
    if wl and ip not in wl:
        logger.warning(f"管理接口非白名单IP访问: {ip} {path}")
        await _log_operation(db, request, "admin_auth_denied", target_type="auth",
                             detail={"reason": "ip_not_in_whitelist", "path": path})
        raise AdminAuthDenied()
    key = f"admin_fail:{ip}"
    # 已达失败上限的 IP 在锁定期内直接拒绝，不再走令牌比对，阻断暴力破解。
    # 内存计数与 Redis 计数取较大值，任一通道判定锁定即拒绝，Redis 故障时防护不再整体失效。
    cnt = _local_fail_count(ip)
    try:
        cnt = max(cnt, int(await redis_client.get(key) or 0))
    except Exception:
        logger.warning("管理令牌失败计数读取 Redis 失败，本轮改用进程内计数判定锁定")
    if cnt >= settings.RATE_LIMIT_ADMIN_FAIL_LOCK:
        logger.warning(f"管理接口锁定期内访问被拒绝: IP={ip} 失败计数={cnt}")
        await _log_operation(db, request, "admin_auth_denied", target_type="auth",
                             detail={"reason": "locked", "fail_count": cnt, "path": path})
        raise AdminAuthDenied()
    # 常量时间比较，避免时序侧信道泄露凭证信息；密码源优先读库中哈希（控制台可改），回落 .env
    if not x_admin_token or not await credential_svc.verify_login_password(db, x_admin_token):
        # 失败计数：连续失败 N 次锁定一段时间。两条通道都写，谁先达上限都能锁住。
        cnt = _local_fail_incr(ip)
        try:
            rc = await redis_client.incr(key)
            if rc == 1:
                await redis_client.expire(key, settings.RATE_LIMIT_ADMIN_LOCK_SECONDS)
            cnt = max(cnt, rc)
        except Exception:
            logger.debug("admin 失败计数 Redis incr 不可用，回退本地计数 ip=%s", ip)
        locked_now = cnt >= settings.RATE_LIMIT_ADMIN_FAIL_LOCK
        if locked_now:
            logger.error(f"管理令牌连续失败 {cnt} 次，IP={ip} 已锁定")
        # token_empty 区分「无令牌扫描器探测」与「带错令牌」（后者可能是配置错/离职人员），
        # 令牌内容绝不入审计，避免审计库反成泄露面。
        await _log_operation(db, request, "admin_auth_denied", target_type="auth",
                             detail={"reason": "lock_triggered" if locked_now else "bad_token",
                                     "fail_count": cnt, "token_empty": not x_admin_token, "path": path})
        raise AdminAuthDenied()
    # 成功则清除失败计数
    _LOCAL_ADMIN_FAIL.pop(ip, None)
    try:
        await redis_client.delete(f"admin_fail:{ip}")
    except Exception:
        logger.debug("admin 失败计数 Redis 清除不可用，忽略 ip=%s", ip)
    # prior_fail>0 表示该 IP 此前有失败尝试后携正确令牌通过，值得运维关注（手误或撞库成功）
    await _log_operation(db, request, "admin_auth_granted", target_type="auth",
                         detail={"reason": "ok", "prior_fail": cnt, "path": path})
    return True


# 卡券兑换单的支付渠道标识（与 services.card.CARD_PAY_CHANNEL 一致）。
# 刻意写成字面量而非 import：卡券模块可以单独回滚删除，若此处 import 它，
# 一旦模块缺失整个 app 都起不来 —— 一个可选业务模块不能把整站带崩。
CARD_CHANNEL = "card"


async def _check_operate_password(req, db: AsyncSession):
    """敏感操作的二次密码校验（fail-closed）。返回错误信息或 None。
    密码源优先读库中 PBKDF2 哈希（控制台可随时修改），未设置时回落 .env；
    校验统一走 credential 的常量时间比较，避免时序侧信道。

    原实现「未配置则不强制」（fail-open）：退款、提现打款确认、改会员
    等资金/资产类操作在运维漏配操作密码时，全部退化为仅凭登录令牌即可执行——
    防护强度反而低于卡券模块（admin_card._operate_password_error 同场景是
    fail-closed）。现对齐卡券口径：未配置即拒绝并给出配置路径，堵住
    「忘了配密码 → 任何拿到登录密码的人都能划走资金」的后门。
    引导路径：/credentials/update 在操作密码未配置时无需旧密码即可设置初始值
    （bootstrap 分支保留），管理员按提示自助配置后即可恢复操作。"""
    if not await credential_svc.operate_password_configured(db):
        return ("未配置操作密码，该敏感操作已按安全策略禁用，"
                "请在控制台「改密码」或后端环境变量中配置操作密码后重试")
    if not await credential_svc.verify_operate_password(db, req.operate_password):
        return "操作密码错误"
    return None


def _like_escape(value: str) -> str:
    """转义 LIKE 通配符，需与 like(..., escape="\\") 配合使用。
    管理端搜索关键字直接拼进 LIKE 模式：未转义时 % 会匹配全表（一次搜索扫全表）、
    _ 会匹配任意单字符，使搜索结果与运营预期不符，也可被用来放大查询开销。"""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
def _mask_phone(p):
    """手机号脱敏（管理端列表页）：11 位手机号保留前 3 后 4。
    列表接口可分页遍历全站用户，明文下发手机号等于给
    管理令牌附赠一个「全量手机号导出」接口；运营需要完整号码联系用户时走
    用户详情页（单用户、有明确业务场景），与提现账号「列表脱敏/详情门禁」同口径。
    非 11 位（历史脏数据/座机）统一只留前 2 位，短值直接全遮，宁过度不泄露。"""
    s = (p or "").strip()
    if not s:
        return None
    if len(s) == 11 and s.isdigit():
        return s[:3] + "****" + s[-4:]
    return (s[:2] + "****") if len(s) > 4 else "****"


# ==================== 凭证管理（登录/操作密码自助修改） ====================
@router.post("/credentials/update")
async def admin_credential_update(request: Request,
                                  payload: dict = Body(...),
                                  db: AsyncSession = Depends(get_db),
                                  is_admin: bool = Depends(require_admin)):
    """使用者自助修改登录密码/操作密码。需同时通过当前登录密码+当前操作密码（双因子重认证，
    防会话被劫持后单凭会话改密夺号）；新密码以 PBKDF2 哈希落库、即时生效且重启不丢；
    全程审计，响应不返回任何哈希/明文。"""
    if not is_admin:
        return error(ErrorCode.ADMIN_LOCKED, "登录密码无效或已被锁定")
    target = str(payload.get("target") or "").strip()
    if target not in ("login", "operate"):
        return error(ErrorCode.PARAM_ERROR, "target 仅支持 login / operate")
    cur_login = payload.get("current_login_password") or ""
    cur_operate = payload.get("current_operate_password") or ""
    new_pwd = payload.get("new_password") or ""
    confirm = payload.get("confirm_password", new_pwd)
    if not await credential_svc.verify_login_password(db, cur_login):
        return error(ErrorCode.NO_PERMISSION, "当前登录密码错误")
    if await credential_svc.operate_password_configured(db) and \
            not await credential_svc.verify_operate_password(db, cur_operate):
        return error(ErrorCode.NO_PERMISSION, "当前操作密码错误")
    if not isinstance(new_pwd, str) or not (8 <= len(new_pwd) <= 128):
        return error(ErrorCode.PARAM_ERROR, "新密码长度需为 8~128 位")
    if not hmac.compare_digest(confirm, new_pwd):
        return error(ErrorCode.PARAM_ERROR, "两次输入的新密码不一致")
    current = cur_login if target == "login" else cur_operate
    if hmac.compare_digest(new_pwd, current):
        return error(ErrorCode.PARAM_ERROR, "新密码不能与当前密码相同")
    if target == "login" and hmac.compare_digest(new_pwd, "change-me-admin-token"):
        return error(ErrorCode.PARAM_ERROR, "新密码不能为代码默认值")
    await credential_svc.set_password(db, target, new_pwd)
    await db.commit()
    await _log_operation(db, request, "credential_change", "credential", target,
                         {"target": target})
    return success({"target": target}, msg="密码已更新，立即生效")


# ==================== 仪表盘 ====================
@router.get("/dashboard")
async def dashboard(db: AsyncSession = Depends(get_db), is_admin: bool = Depends(require_admin)):
    if not is_admin:
        return error(ErrorCode.ADMIN_LOCKED, "管理令牌无效或已被锁定")
    today = datetime.now().strftime("%Y-%m-%d")
    order_total = (await db.execute(select(func.coalesce(func.count(Order.id), 0)))).scalar() or 0
    # 卡券兑换单同样是 status='completed'，但它是 0 元权益载体、不产生任何收入，
    # 计入「已支付订单数」会让该指标随渠道发卡量虚增，运营据此算付费转化率会偏高。
    # revenue 是求和、0 元不影响，无需改动。
    # 用 coalesce 而不是 `pay_channel != 'card'`：历史订单的 pay_channel 可能为 NULL，
    # 而 `NULL != 'card'` 求值为 NULL（非真），会把它们一并排除掉，反而漏算。
    paid_total = (await db.execute(
        select(func.coalesce(func.count(Order.id), 0)).where(
            Order.status == "completed",
            func.coalesce(Order.pay_channel, "") != CARD_CHANNEL))).scalar() or 0
    revenue = (await db.execute(
        select(func.coalesce(func.sum(Order.amount), 0)).where(Order.status == "completed"))).scalar() or 0
    today_revenue = (await db.execute(
        select(func.coalesce(func.sum(Order.amount), 0)).where(
            Order.status == "completed", func.date(Order.paid_at) == today))).scalar() or 0
    vip_month = (await db.execute(
        select(func.coalesce(func.count(UserMembership.id), 0)).where(UserMembership.level == "month"))).scalar() or 0
    vip_year = (await db.execute(
        select(func.coalesce(func.count(UserMembership.id), 0)).where(UserMembership.level == "year"))).scalar() or 0
    vip_lifetime = (await db.execute(
        select(func.coalesce(func.count(UserMembership.id), 0)).where(UserMembership.level == "lifetime"))).scalar() or 0
    user_total = (await db.execute(
        select(func.coalesce(func.count(User.id), 0)).where(User.status == 1))).scalar() or 0
    auditing_wd = (await db.execute(
        select(func.coalesce(func.sum(Withdrawal.amount), 0)).where(Withdrawal.status == "auditing"))).scalar() or 0
    auditing_count = (await db.execute(
        select(func.coalesce(func.count(Withdrawal.id), 0)).where(Withdrawal.status == "auditing"))).scalar() or 0
    pending_commission = (await db.execute(
        select(func.coalesce(func.sum(CommissionLog.amount), 0)).where(CommissionLog.status == "pending"))).scalar() or 0
    # 退款失败数（需人工介入）
    refund_failed = (await db.execute(
        select(func.coalesce(func.count(Refund.id), 0)).where(Refund.status == "failed"))).scalar() or 0
    # 退款处理中数（渠道已受理、结论未回）。与退款失败同属「不知道就等于没处理」的待办：
    # 回调可能因验签配置错误或平台重试耗尽而永不到达，退款单就停在 processing；
    # 概览不曝光，管理员既看不到「退款成功」，也无从判断该不该重发。
    refund_processing = (await db.execute(
        select(func.coalesce(func.count(Refund.id), 0)).where(
            Refund.status.in_(["processing", "pending_refund"])))).scalar() or 0
    # 未处理对账差错数。与退款失败同属「不处理就是资损」的待办，必须在概览页曝光：
    # 对账每日自动跑，差错只入库不改账，没人看就等于没对。
    recon_unresolved = (await db.execute(
        select(func.coalesce(func.count(ReconciliationDiff.id), 0)).where(
            ReconciliationDiff.resolved == 0))).scalar() or 0
    # 待开具与待红冲条数。与待审提现、未处理对账差错同属「不处理就出事」的待办队列：
    # 开票申请不报错也不告警，只会默默超期，而超期不开属《发票管理办法》第三十五条
    # 的罚则情形；待红冲则意味着平台账面收入与税局申报收入不符。不上概览就等于没人会看。
    # 包 try 而不直接查：存量 MySQL 库如果还没建 invoice_requests 表，这里会抛 Table doesn't exist，
    # 不拦住就会让整张概览页白屏——为一张可选表而牺牲收入/订单这些必需指标不划算。
    # 取不到时下发 None，前端据此不渲染该卡片（而不是渲染一个假的 0，
    # 0 会让人误以为「没有待开票」，与「表还没建」是两回事）。
    try:
        inv_counts = await _invoice_counts(db)
        invoice_pending, invoice_red = inv_counts["pending_total"], inv_counts["red_flush_total"]
    except Exception as e:
        logger.warning(f"[发票] 概览计数读取失败（多为 invoice_requests 表未建，请补执行 sql/migrations/ 增量脚本）: {e}")
        invoice_pending, invoice_red = None, None
    return success({
        "user_total": user_total, "order_total": order_total, "paid_total": paid_total,
        "revenue": float(revenue), "today_revenue": float(today_revenue),
        "vip_month": vip_month, "vip_year": vip_year, "vip_lifetime": vip_lifetime,
        "auditing_withdraw_amount": float(auditing_wd), "auditing_withdraw_count": auditing_count,
        "pending_commission": float(pending_commission), "refund_failed_count": refund_failed,
        "refund_processing_count": refund_processing,
        "reconcile_unresolved": recon_unresolved,
        "invoice_pending_count": invoice_pending, "invoice_red_flush_count": invoice_red,
    })


# ==================== 订单管理 ====================
@router.get("/orders")
async def admin_orders(status_filter: str = Query(None, alias="status"), sku: str = Query(None),
                       keyword: str = Query(None), paid_on: str = Query(None),
                       paid_only: int = Query(0, ge=0, le=1),
                       page: int = Query(1, ge=1),
                       page_size: int = Query(20, ge=1, le=100),
                       db: AsyncSession = Depends(get_db), is_admin: bool = Depends(require_admin)):
    if not is_admin:
        return error(ErrorCode.ADMIN_LOCKED, "管理令牌无效或已被锁定")
    stmt = select(Order)
    if status_filter:
        stmt = stmt.where(Order.status == status_filter)
    # 概览「今日收入」卡片点击直达：按支付日期定位当天已付单，口径与 dashboard 的 today_revenue 一致
    if paid_on:
        stmt = stmt.where(func.date(Order.paid_at) == paid_on)
    # 概览「已付订单」卡片点击直达：口径与 dashboard 的 paid_total 完全一致
    # （completed 且非卡券渠道）；卡券兑换单是 0 元权益载体，计入已付订单会虚增付费转化
    if paid_only:
        stmt = stmt.where(Order.status == "completed", func.coalesce(Order.pay_channel, "") != CARD_CHANNEL)
    if sku:
        stmt = stmt.where(Order.sku_code == sku)
    if keyword:
        kw = keyword.strip()
        # 订单号优先前缀匹配走索引，用户ID精确匹配
        # isascii 守卫：str.isdigit() 对上标字符（"²"）也返回 True，但 int("²") 抛
        # ValueError → 未捕获 500；限定 ASCII 数字后该分支的 int() 恒安全。
        if kw.isascii() and kw.isdigit():
            stmt = stmt.where(or_(Order.order_no.like(f"{kw}%"), Order.user_id == int(kw)))
        else:
            stmt = stmt.where(Order.order_no.like(f"{_like_escape(kw)}%", escape="\\"))
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar() or 0
    result = await db.execute(
        stmt.order_by(Order.id.desc()).offset((page - 1) * page_size).limit(page_size))
    items = [{
        "id": x.id, "order_no": x.order_no, "user_id": x.user_id, "sku_code": x.sku_code,
        "product_type": x.product_type, "product_name": x.product_name, "amount": float(x.amount),
        "status": x.status, "pay_channel": x.pay_channel, "pay_trade_no": x.pay_trade_no,
        "inviter_id": x.inviter_id,
        "paid_at": x.paid_at.strftime("%Y-%m-%d %H:%M") if x.paid_at else None,
        "created_at": x.created_at.strftime("%Y-%m-%d %H:%M") if x.created_at else None,
    } for x in result.scalars().all()]
    return success({"list": items, "total": total, "page": page, "page_size": page_size})


@router.get("/orders/{order_id}")
async def admin_order_detail(order_id: int, db: AsyncSession = Depends(get_db),
                             is_admin: bool = Depends(require_admin)):
    if not is_admin:
        return error(ErrorCode.ADMIN_LOCKED, "管理令牌无效或已被锁定")
    order = (await db.execute(select(Order).where(Order.id == order_id))).scalar_one_or_none()
    if not order:
        return error(ErrorCode.ORDER_INVALID, "订单不存在")
    refunds = (await db.execute(select(Refund).where(Refund.order_id == order_id))).scalars().all()
    # ensure-report 曾把 biz_data 以 json.dumps 后的字符串写入 JSON 列，
    # 存量行 ORM 读回来是 str，后台详情会显示成一坨转义文本，客服无法核对出生信息。
    # 仅做展示层兼容：本来就是 None、或解析失败的保持原样，不改变字段语义。
    biz_view = order.biz_data
    if isinstance(biz_view, str):
        try:
            biz_view = json.loads(biz_view)
        except Exception:
            logger.debug("order biz_data 非法 JSON，保持原样展示 order_id=%s", order.id)
    return success({
        "id": order.id, "order_no": order.order_no, "user_id": order.user_id,
        "sku_code": order.sku_code, "product_type": order.product_type,
        "product_name": order.product_name, "amount": float(order.amount), "status": order.status,
        "pay_channel": order.pay_channel, "pay_trade_no": order.pay_trade_no,
        "input_snapshot": order.input_snapshot, "biz_data": biz_view, "inviter_id": order.inviter_id,
        # 双向定位快照：财务/客服用 user_id + 登录标识两个维度核对买家身份
        "login_id_type": order.login_id_type, "login_id_value": order.login_id_value,
        "paid_at": order.paid_at.strftime("%Y-%m-%d %H:%M:%S") if order.paid_at else None,
        "fulfilled_at": order.fulfilled_at.strftime("%Y-%m-%d %H:%M:%S") if order.fulfilled_at else None,
        "created_at": order.created_at.strftime("%Y-%m-%d %H:%M:%S") if order.created_at else None,
        "refunds": [{
            "id": r.id, "refund_no": r.refund_no, "reason": r.reason, "status": r.status,
            "fail_reason": r.fail_reason,
            "created_at": r.created_at.strftime("%Y-%m-%d %H:%M") if r.created_at else None,
        } for r in refunds],
    })


@router.post("/orders/{order_id}/refund")
async def admin_refund(order_id: int, req: AdminRefundRequest, request: Request,
                       db: AsyncSession = Depends(get_db), is_admin: bool = Depends(require_admin)):
    if not is_admin:
        return error(ErrorCode.ADMIN_LOCKED, "管理令牌无效或已被锁定")
    pw_err = await _check_operate_password(req, db)
    if pw_err:
        return error(ErrorCode.NO_PERMISSION, pw_err)
    order = (await db.execute(row_lock(select(Order).where(Order.id == order_id)))).scalar_one_or_none()
    if not order:
        return error(ErrorCode.ORDER_INVALID, "订单不存在")
    # 退款幂等——已有成功/处理中的退款则拒绝
    exist = (await db.execute(select(Refund).where(
        Refund.order_id == order_id,
        Refund.status.in_(["refunded", "processing", "pending_refund"])))).scalars().first()
    if exist:
        return error(ErrorCode.REFUND_NOT_ELIGIBLE, "该订单已退款或退款处理中，请勿重复操作")
    if order.status not in ("completed", "refund_pending"):
        return error(ErrorCode.REFUND_NOT_ELIGIBLE, f"订单状态为{order.status}，不可退款")
    # 卡券兑换单（pay_channel='card'）状态恒为 completed，能顺利通过上一行校验。
    # 若继续走退款：apply_refund 会对一个不存在的支付单发起 0 元退款，一旦返回成功，
    # revoke_refunded_order 就会撤销用户已到账的权益/会员，而卡券本身已是 used、
    # 无法重兑 —— 用户白丢已购商品且系统内无恢复路径。
    # 卡券的回收必须走「作废未使用卡」，永远不能走订单退款。
    if (order.pay_channel or "") == CARD_CHANNEL:
        return error(ErrorCode.REFUND_NOT_ELIGIBLE,
                     "卡券兑换订单不支持退款，请通过卡券作废流程处理")
    # 卡券单之外，还有一类同样「无真实资金流入」的订单能通过上面的状态校验——
    # 会员期内 ensure-report 产生的 0 元解读单（pay_channel='member', amount=0），
    # 状态恒为 completed。对它退款同样只会命中一笔 0 元退款：模拟支付模式下
    # apply_refund 直接判成功，revoke_refunded_order 随即撤销该会员刚拿到的免费权益，
    # 并留下一条与真实资金无关的退款单；真实渠道下则是对不存在的商户单号发起退款、
    # 重试 3 次后转人工告警。统一用 has_real_payment 判定，与用户端 _self_refund_block、
    # 定时任务的两条退款路径保持同一口径。
    if not has_real_payment(order):
        return error(ErrorCode.REFUND_NOT_ELIGIBLE, no_payment_reason(order))
    # 并发护栏：refunds.order_id 并非唯一约束，上面「SELECT 判重 → INSERT」在无锁下会被并发穿透
    # （两个管理员同时点退款都通过判重），产生多条退款单并向支付平台发起多笔重复退款；
    # apply_refund 每次都新生成 refund_no，平台不会把它们视为同一笔，钱会被真退两次。
    # 与用户端只允许 completed 不同，这里额外允许 refund_pending——用户申请退款被平台拒绝后，
    # 订单会停在该状态、退款单留在 failed，需要管理员强制退款兜底。
    prev_status = order.status
    # 第一层护栏：Redis 互斥锁，与计算 / ensure-report / 实时测算发起测算同一套路，覆盖上面两种入口状态。
    lock_key = f"lock:admin_refund:{order_id}"
    # The completed->refund_pending CAS below is the authoritative guard, so a
    # Redis outage may safely degrade to the database-backed path.
    lock_token = await redis_acquire_lock(
        redis_client, lock_key, 60, fail_closed=False)
    if not lock_token:
        return error(ErrorCode.RATE_LIMIT, "该订单退款正在处理，请稍候再试")
    try:
        # 第二层护栏：completed -> refund_pending 的原子抢占。Redis 故障降级放行时仍能兜住，
        # 且这是一次真实状态变更，MySQL / SQLite 的 affected_rows 口径都可靠。
        # prev_status 已是 refund_pending 时不做同值 CAS：MySQL 的 affected_rows 只统计
        # 「值真正改变的行」，同值 UPDATE 恒返回 0，会把管理员的兜底强制退款永久误判成
        # 「已在退款流程中」，这笔订单从此谁都退不了。该分支的互斥由上面的 Redis 锁
        # 与 row_lock（MySQL 下 SELECT ... FOR UPDATE 已串行化同一订单）共同承担。
        if prev_status == "completed":
            claimed = (await db.execute(
                update(Order).where(Order.id == order.id, Order.status == "completed")
                .values(status="refund_pending", active_key=None))).rowcount
            if not claimed:
                return error(ErrorCode.REFUND_NOT_ELIGIBLE, "该订单已在退款流程中，请勿重复操作")
        # 退款单号入库即预生成并原样传给平台。此前 apply_refund 内部临时生成——
        # 进程在拿到结果前崩溃会把空单号留在 Refund 行，retry_failed_refunds 重试时
        # 会再生成新单号向平台发起第二笔真实退款；预生成后重试复用同一 out_refund_no，
        # 微信/支付宝对重复单号幂等返回，杜绝“同订单二次真实退款”。
        refund_no = gen_refund_no()
        refund = Refund(order_id=order.id, user_id=order.user_id, reason=req.reason,
                        description=req.remark, status="pending_refund", refund_no=refund_no)
        db.add(refund)
        await db.flush()
        # 与用户端 /api/order/refund 同口径：退款单与订单抢占
        # 状态先持久化再调渠道。否则「渠道已受理 → 本地事务回滚」的窗口内，
        # 再次发起退款会生成新 refund_no 向平台退第二笔真钱。
        await db.commit()
        result = await apply_refund(
            order_no=order.order_no, pay_trade_no=order.pay_trade_no or "",
            amount=float(order.amount), reason=req.reason, channel=order.pay_channel,
            order_amount=float(order.amount), refund_no=refund_no)
        refund.refund_no = result.refund_no or refund_no
        if result.ok:
            refund.status = "refunded"
            order.status = "refunded"
            order.active_key = None
            warn = await revoke_refunded_order(db, order)
            await _log_operation(db, request, "admin_refund", "order", order_id,
                                 {"order_no": order.order_no, "amount": float(order.amount),
                                  "reason": req.reason, "revoke_warn": warn})
            msg = "退款成功，权益已回收、佣金已冲回" + ("（注意：权益回收有异常请核查）" if warn else "")
            return success(msg=msg)
        elif result.status == "processing":
            refund.status = "processing"
            order.status = "refund_pending"
            order.active_key = None
            await _log_operation(db, request, "admin_refund_processing", "order", order_id,
                                 {"order_no": order.order_no})
            return success(msg="退款处理中，以支付平台最终结果为准")
        else:
            refund.status = "failed"
            refund.fail_reason = (result.msg or "支付平台退款失败")[:200]
            # 退款失败：把订单还原为抢占前的状态。此时权益并未回收，用户仍可正常使用，
            # 若让它长期停在「退款中」，用户既没拿到退款、又看不到自己的已完成订单。
            # 必须用 Core UPDATE 而不是 order.status = prev_status：抢占那条 UPDATE 之后，
            # ORM 实例内存里的 status 可能仍是抢占前的旧值，赋相同值不会生成 UPDATE，
            # 库里就会错误地停在 refund_pending。与 api/order.py 用户端退款同一处理。
            # 同 api/order.py：带 refund_pending 守卫，避免并发下把已置为 refunded 的订单复活
            await db.execute(update(Order).where(
                Order.id == order.id, Order.status == "refund_pending").values(status=prev_status))
            await _log_operation(db, request, "admin_refund_failed", "order", order_id,
                                 {"order_no": order.order_no, "fail": result.msg})
            return error(ErrorCode.REFUND_FAILED, "支付平台退款调用失败：" + (result.msg or "未知错误"))
    finally:
        # 必须带令牌释放：退款要等支付平台返回，耗时可能超过 60s TTL，
        # 无条件 DELETE 会删掉下一个管理员刚抢到的锁，兜底退款分支因此失去唯一护栏。
        await redis_release_lock(redis_client, lock_key, lock_token)


# ==================== 用户管理 ====================
@router.get("/users")
async def admin_users(keyword: str = Query(None), page: int = Query(1, ge=1),
                      page_size: int = Query(20, ge=1, le=100),
                      db: AsyncSession = Depends(get_db), is_admin: bool = Depends(require_admin)):
    if not is_admin:
        return error(ErrorCode.ADMIN_LOCKED, "管理令牌无效或已被锁定")
    stmt = select(User).where(User.status == 1)
    if keyword:
        kw = keyword.strip()
        cond = [User.nickname.contains(kw, autoescape=True),
                User.oa_openid.contains(kw, autoescape=True),
                User.phone.contains(kw, autoescape=True),
                # 双向定位：登录标识（设备码）也可直接搜人，客服拿订单快照里的
                # login_id_value 就能反查到账号
                User.device_code.contains(kw, autoescape=True)]
        if kw.isdigit():
            cond.append(User.id == int(kw))
        stmt = stmt.where(or_(*cond))
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar() or 0
    result = await db.execute(
        stmt.order_by(User.id.desc()).offset((page - 1) * page_size).limit(page_size))
    items = [{
        "id": u.id, "nickname": u.nickname, "phone": _mask_phone(u.phone),
        "oa_openid": (u.oa_openid[:10] + "***") if u.oa_openid else None,
        "inviter_id": u.inviter_id,
        "created_at": u.created_at.strftime("%Y-%m-%d %H:%M") if u.created_at else None,
    } for u in result.scalars().all()]
    return success({"list": items, "total": total, "page": page, "page_size": page_size})


@router.get("/users/{user_id}")
async def admin_user_detail(user_id: int, request: Request, db: AsyncSession = Depends(get_db),
                            is_admin: bool = Depends(require_admin)):
    if not is_admin:
        return error(ErrorCode.ADMIN_LOCKED, "管理令牌无效或已被锁定")
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user:
        return error(ErrorCode.NO_PERMISSION, "用户不存在")
    # 详情页明文下发手机号与全部登录标识（列表已脱敏），与提现/发票的
    # 「明文查看必留痕」原则对齐补一条审计：谁在何时看过谁的明文个人信息必须可追溯。
    # 详情本身不设操作密码门禁——核对场景高频，二次密码会显著拖慢客服响应，
    # 留痕已满足「事后可查」的最小要求（收紧为门禁属运营策略决策，不在代码层强制）。
    await _log_operation(db, request, "user_view_detail", "user", user_id,
                         {"fields": "phone,identities"})
    member = await get_member_status(db, user_id)  # 统一走实时状态
    dist = (await db.execute(select(Distributor).where(Distributor.user_id == user_id))).scalar_one_or_none()
    order_cnt = (await db.execute(
        select(func.coalesce(func.count(Order.id), 0)).where(Order.user_id == user_id))).scalar() or 0
    paid_amount = (await db.execute(
        select(func.coalesce(func.sum(Order.amount), 0)).where(
            Order.user_id == user_id, Order.status == "completed"))).scalar() or 0
    ent_cnt = (await db.execute(
        select(func.coalesce(func.count(UserEntitlement.id), 0)).where(UserEntitlement.user_id == user_id))).scalar() or 0
    recent = (await db.execute(
        select(Order).where(Order.user_id == user_id).order_by(Order.id.desc()).limit(10))).scalars().all()
    # 双向定位：台账展示该账号全部登录标识（含历史），客服/财务据此双向核对。
    # 详情内不脱敏：后台在管理令牌门后，核对场景需要完整值才能与订单快照比对。
    identities = await identity_svc.identities_of_user(db, user_id)
    return success({
        "user": {
            "id": user.id, "nickname": user.nickname, "phone": user.phone,
            "avatar_url": user.avatar_url, "inviter_id": user.inviter_id,
            "invited_at": user.invited_at.strftime("%Y-%m-%d %H:%M") if user.invited_at else None,
            "created_at": user.created_at.strftime("%Y-%m-%d %H:%M") if user.created_at else None,
            "last_login_type": user.last_login_type, "last_login_value": user.last_login_value,
        },
        "identities": identities,
        "membership": member,
        "distributor": {
            "invite_code": dist.invite_code, "status": dist.status,
            "total_commission": float(dist.total_commission or 0),
            "pending_commission": float(dist.pending_commission or 0),
            "available_commission": float(dist.available_commission or 0),
            "withdrawn_commission": float(dist.withdrawn_commission or 0),
            "debt_commission": float(dist.debt_commission or 0),
            "invite_count": dist.invite_count, "paid_count": dist.paid_count,
        } if dist else None,
        "stats": {"order_count": order_cnt, "paid_amount": float(paid_amount), "entitlement_count": ent_cnt},
        "recent_orders": [{
            "id": o.id, "order_no": o.order_no, "product_name": o.product_name,
            "amount": float(o.amount), "status": o.status,
            "created_at": o.created_at.strftime("%Y-%m-%d %H:%M") if o.created_at else None,
        } for o in recent],
    })


@router.post("/users/{user_id}/membership")
async def admin_set_membership(user_id: int, req: AdminMembershipRequest, request: Request,
                               db: AsyncSession = Depends(get_db), is_admin: bool = Depends(require_admin)):
    if not is_admin:
        return error(ErrorCode.ADMIN_LOCKED, "管理令牌无效或已被锁定")
    pw_err = await _check_operate_password(req, db)
    if pw_err:
        return error(ErrorCode.NO_PERMISSION, pw_err)
    user = (await db.execute(select(User).where(User.id == user_id, User.status == 1))).scalar_one_or_none()
    if not user:
        return error(ErrorCode.NO_PERMISSION, "用户不存在")
    before = await get_member_status(db, user_id)
    m = await admin_grant_membership(db, user_id, req.action, req.days)
    await _log_operation(db, request, f"membership_{req.action}", "user", user_id,
                         {"before": before, "days": req.days, "remark": req.remark})
    return success({"level": m.level,
                    "expire_at": m.expire_at.strftime("%Y-%m-%d %H:%M") if m.expire_at else None},
                   msg="会员状态已更新")


# ==================== 分销管理 ====================
@router.get("/distributors")
async def admin_distributors(page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100),
                             db: AsyncSession = Depends(get_db), is_admin: bool = Depends(require_admin)):
    if not is_admin:
        return error(ErrorCode.ADMIN_LOCKED, "管理令牌无效或已被锁定")
    stmt = select(Distributor)
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar() or 0
    result = await db.execute(
        stmt.order_by(Distributor.total_commission.desc())
        .offset((page - 1) * page_size).limit(page_size))
    items = [{
        "id": d.id, "user_id": d.user_id, "invite_code": d.invite_code, "status": d.status,
        "level": int(d.level or 0),
        "verified_paid_count": int(d.verified_paid_count or 0),
        "exam_passed": bool(int(d.exam_passed or 0)),
        "link_disabled": bool(int(d.link_disabled or 0)),
        # 原先是 d.real_name[0] + "**"。加密后 real_name 是 enc:v1:… 开头的密文，
        # 取首字会得到固定的 "e**"——既没脱敏出任何有用信息，还让运营看不出“到底绑没绑
        # 实名”（风控要靠它判断）。mask_name 先解密再脱敏，且兼容存量明文行。
        "real_name_mask": (mask_name(d.real_name) or None),
        "frozen_until": d.frozen_until.strftime("%Y-%m-%d %H:%M") if d.frozen_until else None,
        "total_commission": float(d.total_commission or 0),
        "pending_commission": float(d.pending_commission or 0),
        "available_commission": float(d.available_commission or 0),
        "withdrawn_commission": float(d.withdrawn_commission or 0),
        "debt_commission": float(d.debt_commission or 0),
        "invite_count": d.invite_count, "paid_count": d.paid_count,
    } for d in result.scalars().all()]
    return success({"list": items, "total": total, "page": page, "page_size": page_size})


@router.get("/commissions")
async def admin_commissions(status_filter: str = Query(None, alias="status"), page: int = Query(1, ge=1),
                            page_size: int = Query(20, ge=1, le=100),
                            db: AsyncSession = Depends(get_db), is_admin: bool = Depends(require_admin)):
    if not is_admin:
        return error(ErrorCode.ADMIN_LOCKED, "管理令牌无效或已被锁定")
    stmt = select(CommissionLog)
    if status_filter:
        stmt = stmt.where(CommissionLog.status == status_filter)
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar() or 0
    result = await db.execute(
        stmt.order_by(CommissionLog.id.desc()).offset((page - 1) * page_size).limit(page_size))
    items = [{
        "id": x.id, "distributor_id": x.distributor_id, "buyer_id": x.buyer_id,
        "order_no": x.order_no, "order_amount": float(x.order_amount),
        "rate": float(x.rate) if x.rate is not None else None, "amount": float(x.amount),
        "status": x.status,
        "created_at": x.created_at.strftime("%Y-%m-%d %H:%M") if x.created_at else None,
    } for x in result.scalars().all()]
    return success({"list": items, "total": total, "page": page, "page_size": page_size})


# ==================== 会员名录（概览「月/年/终身会员」点击直达） ====================
@router.get("/memberships")
async def admin_memberships(level: str = Query(None), page: int = Query(1, ge=1),
                            page_size: int = Query(20, ge=1, le=100),
                            db: AsyncSession = Depends(get_db), is_admin: bool = Depends(require_admin)):
    """会员记录列表。level 过滤口径与 dashboard 的 vip_month/vip_year/vip_lifetime 完全一致
   （同为 user_memberships.level 等值计数），保证概览数字点进来就是同一批记录。"""
    if not is_admin:
        return error(ErrorCode.ADMIN_LOCKED, "管理令牌无效或已被锁定")
    stmt = select(UserMembership, User).outerjoin(User, User.id == UserMembership.user_id)
    if level and level != "all":
        stmt = stmt.where(UserMembership.level == level)
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar() or 0
    result = await db.execute(
        stmt.order_by(UserMembership.id.desc()).offset((page - 1) * page_size).limit(page_size))
    items = [{
        "id": m.id, "user_id": m.user_id, "level": m.level,
        "nickname": u.nickname if u else None, "phone": _mask_phone(u.phone) if u else None,
        "start_at": m.start_at.strftime("%Y-%m-%d %H:%M") if m.start_at else None,
        "expire_at": m.expire_at.strftime("%Y-%m-%d %H:%M") if m.expire_at else None,
        "source_order_no": m.source_order_no,
    } for m, u in result.all()]
    return success({"list": items, "total": total, "page": page, "page_size": page_size})


# ==================== 退款售后（概览「退款失败待处理」点击直达） ====================
@router.get("/refunds")
async def admin_refunds(status_filter: str = Query(None, alias="status"), page: int = Query(1, ge=1),
                        page_size: int = Query(20, ge=1, le=100),
                        db: AsyncSession = Depends(get_db), is_admin: bool = Depends(require_admin)):
    """退款单列表。失败单由定时任务 retry_failed_refunds 自动重试，本页供人工核对失败原因与重试次数。"""
    if not is_admin:
        return error(ErrorCode.ADMIN_LOCKED, "管理令牌无效或已被锁定")
    stmt = select(Refund, Order).outerjoin(Order, Order.id == Refund.order_id)
    if status_filter and status_filter != "all":
        stmt = stmt.where(Refund.status == status_filter)
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar() or 0
    result = await db.execute(
        stmt.order_by(Refund.id.desc()).offset((page - 1) * page_size).limit(page_size))
    items = [{
        "id": r.id, "refund_no": r.refund_no, "order_no": o.order_no if o else None,
        "user_id": r.user_id, "amount": float(o.amount) if o else 0.0,
        "status": r.status, "reason": r.reason, "fail_reason": r.fail_reason,
        "retry_count": r.retry_count,
        # 订单当前状态与渠道：退款结论最终落在订单上（refunded/completed/refund_pending），
        # 只给退款单状态时，管理员看不出这笔钱到底退成没有。
        "order_status": o.status if o else None,
        "channel": o.pay_channel if o else None,
        "created_at": r.created_at.strftime("%Y-%m-%d %H:%M") if r.created_at else None,
        "updated_at": r.updated_at.strftime("%Y-%m-%d %H:%M") if r.updated_at else None,
    } for r, o in result.all()]
    return success({"list": items, "total": total, "page": page, "page_size": page_size})


@router.post("/refunds/{refund_id}/sync")
async def admin_sync_refund(refund_id: int, request: Request,
                            db: AsyncSession = Depends(get_db),
                            is_admin: bool = Depends(require_admin)):
    """向支付渠道主动查一次退款结论并落库（不依赖回调送达）。

    为什么必须有它：退款最终结论原先只来自渠道回调，而回调可能因验签配置错误、发布重启、
    网络抖动或平台重试耗尽而永远不到达——退款单就永久停在「退款中」，管理员既无法确认
    钱到底退没退、也不敢重发。本接口把「渠道事实」拉回来落库，让后台随时能得到结论。
    状态迁移复用 services/refund_state.apply_channel_refund_status：与回调同一函数、同一套
    原子 CAS 与订单还原守卫，因此重复点击、与回调并发都不会把已成功的退款单降级、
    也不会二次回收权益（会员天数二次扣减/佣金二次冲回）。
    """
    if not is_admin:
        return error(ErrorCode.ADMIN_LOCKED, "管理令牌无效或已被锁定")
    refund = (await db.execute(
        select(Refund).where(Refund.id == refund_id))).scalar_one_or_none()
    if not refund:
        return error(ErrorCode.REFUND_FAILED, "退款单不存在")
    if refund.status == "refunded":
        return success({"status": "refunded", "changed": False,
                        "msg": "该退款单已成功，无需同步"})
    if not refund.refund_no:
        return error(ErrorCode.REFUND_FAILED, "该退款单没有渠道退款单号，无法向渠道查询")
    r = await query_refund(refund.refund_no, channel="wechat")
    state = r.get("state")
    if state in ("unsupported", "error"):
        # 查询失败不落任何状态：宁可保持「退款中」让人工继续追问，也不能把查询失败猜成
        # 「退款失败」——那会把订单还原成 completed，而钱可能已经退出去了。
        await _log_operation(db, request, "admin_refund_sync_failed", "refund", refund.id,
                             {"refund_no": refund.refund_no, "error": r.get("msg")})
        return error(ErrorCode.REFUND_FAILED, "渠道查询失败：" + str(r.get("msg") or state))
    before = refund.status
    after = await apply_channel_refund_status(
        db, refund, r.get("refund_status") or "PROCESSING", source="admin_sync")
    await _log_operation(db, request, "admin_refund_sync", "refund", refund.id,
                         {"refund_no": refund.refund_no, "before": before, "after": after,
                          "channel_status": r.get("refund_status")})
    msg = {"refunded": "渠道确认退款成功，订单已置为已退款并回收权益",
           "failed": "渠道最终未退成，订单已还原",
           "processing": "渠道仍在处理中，请稍后再同步"}.get(after, "已同步")
    return success({"status": after, "changed": after != before,
                    "channel_status": r.get("refund_status"), "msg": msg})


# ==================== 提现审核 ====================
@router.get("/withdrawals")
async def admin_withdrawals(status_filter: str = Query("auditing", alias="status"), page: int = Query(1, ge=1),
                            page_size: int = Query(20, ge=1, le=100),
                            db: AsyncSession = Depends(get_db), is_admin: bool = Depends(require_admin)):
    if not is_admin:
        return error(ErrorCode.ADMIN_LOCKED, "管理令牌无效或已被锁定")
    stmt = select(Withdrawal)
    if status_filter and status_filter != "all":
        stmt = stmt.where(Withdrawal.status == status_filter)
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar() or 0
    result = await db.execute(
        stmt.order_by(Withdrawal.id.desc()).offset((page - 1) * page_size).limit(page_size))
    items = [{
        "id": x.id, "withdraw_no": x.withdraw_no, "user_id": x.user_id,
        "amount": float(x.amount), "tax_amount": float(x.tax_amount or 0),
        "actual_amount": float(x.actual_amount) if x.actual_amount is not None else None,
        # 列表页不过二次密码，姓名同样只给脱敏值（原先直接下发明文姓名）。
        "status": x.status, "channel": x.channel, "account_name": mask_name(x.account_name),
        "account_mask": mask_account(x.channel, x.account_no),
        "remark": x.remark,
        "created_at": x.created_at.strftime("%Y-%m-%d %H:%M") if x.created_at else None,
        "audited_at": x.audited_at.strftime("%Y-%m-%d %H:%M") if x.audited_at else None,
    } for x in result.scalars().all()]
    return success({"list": items, "total": total, "page": page, "page_size": page_size})


@router.get("/withdrawals/{withdrawal_id}")
async def admin_withdrawal_detail(withdrawal_id: int, request: Request,
                                  db: AsyncSession = Depends(get_db),
                                  is_admin: bool = Depends(require_admin),
                                  x_operate_password: str = Header(default="", alias="X-Operate-Password")):
    """提现单详情：完整收款账号属敏感信息，配置了操作密码时必须携带二次密码（与后台其他敏感操作同口径）"""
    if not is_admin:
        return error(ErrorCode.ADMIN_LOCKED, "管理令牌无效或已被锁定")
    # 原先只校验 .env 的 ADMIN_OPERATE_PASSWORD，与
    # credential 服务「控制台改密后只认库中 PBKDF2 哈希、.env 旧值立即失效」的
    # 设计相悖：管理员经 /credentials/update 改过操作密码后，本接口仍认 .env
    # 旧值——改密前已泄露/移交的旧密码对「查看完整收款账号」永远有效；更糟的
    # 是 .env 未配而库里已设置时，条件短路直接跳过门禁，任何持有管理令牌者
    # 都能拉到解密后的实名+完整收款账号。改与 admin_audit/_check_operate_password
    # 同口径：库哈希优先、回落 .env，只要任一来源配置了就必须校验通过。
    # 未配置操作密码时同样拒绝（fail-closed，与 _check_operate_password
    # 新口径一致）：本接口解密下发实名+完整收款账号，fail-open 等于「忘了配密码 →
    # 任何持有管理令牌者都能拉到打款要用的全部要素」。
    if not await credential_svc.operate_password_configured(db):
        return error(ErrorCode.NO_PERMISSION,
                     "未配置操作密码，查看完整收款信息已按安全策略禁用，"
                     "请在控制台「改密码」或后端环境变量中配置操作密码后重试")
    if not await credential_svc.verify_operate_password(db, x_operate_password):
        return error(ErrorCode.NO_PERMISSION, "查看完整收款信息需要操作密码")
    wd = (await db.execute(select(Withdrawal).where(Withdrawal.id == withdrawal_id))).scalar_one_or_none()
    if not wd:
        return error(ErrorCode.PARAM_ERROR, "提现单不存在")
    await _log_operation(db, request, "withdraw_view_account", "withdrawal", withdrawal_id)
    # 解密明文供人工打款。strict=True——解不开（密钥被换过或密文被篡改）时必须报错，
    # 绝不能把密文或空串当成收款账号交给运营去打款（钱会打到不存在的账号上）。
    # 同时不能抛 500：密钥问题是运维配置事故，要让后台看到可读原因而不是白屏。
    try:
        plain_name = decrypt_field(wd.account_name, strict=True, field="account_name")
        plain_no = decrypt_field(wd.account_no, strict=True, field="account_no")
    except Exception as e:
        logger.critical(f"[提现详情] 收款信息解密失败，无法打款 withdrawal_id={withdrawal_id}: {e}")
        return error(ErrorCode.SENSITIVE_DECRYPT_FAILED,
                     "收款信息解密失败（密钥变更或数据异常），已记录告警，请联系技术处理后重试")
    return success({
        "id": wd.id, "withdraw_no": wd.withdraw_no, "user_id": wd.user_id,
        "amount": float(wd.amount), "tax_amount": float(wd.tax_amount or 0),
        "actual_amount": float(wd.actual_amount) if wd.actual_amount is not None else None,
        "status": wd.status, "channel": wd.channel,
        "account_name": plain_name, "account_no": plain_no,
        "remark": wd.remark,
        "created_at": wd.created_at.strftime("%Y-%m-%d %H:%M:%S") if wd.created_at else None,
        "audited_at": wd.audited_at.strftime("%Y-%m-%d %H:%M:%S") if wd.audited_at else None,
    })


@router.post("/withdrawals/{withdrawal_id}/audit")
async def admin_audit(withdrawal_id: int, req: AdminAuditRequest, request: Request,
                      db: AsyncSession = Depends(get_db), is_admin: bool = Depends(require_admin)):
    if not is_admin:
        return error(ErrorCode.ADMIN_LOCKED, "管理令牌无效或已被锁定")
    pw_err = await _check_operate_password(req, db)
    if pw_err:
        return error(ErrorCode.NO_PERMISSION, pw_err)
    ok, msg = await audit_withdrawal(db, withdrawal_id, req.action, auditor="admin",
                                     remark=req.remark, refund_count=req.refund_count)
    if not ok:
        return error(ErrorCode.PARAM_ERROR, msg)
    await _log_operation(db, request, f"withdraw_{req.action}", "withdrawal", withdrawal_id,
                         {"remark": req.remark})
    return success(msg=msg)


# ==================== 敏感字段加密运维 ====================
# 密文前缀的 LIKE 匹配串（用于「还是明文」的筛选）。前缀里没有 _ 与 % 通配符，
# 不需转义；若将来改了前缀格式，这里必须同步（见 utils/crypto_field._PREFIX）。
_ENC_PREFIX_LIKE = "enc:v1:%"


@router.post("/crypto/backfill")
async def admin_crypto_backfill(req: AdminCryptoBackfillRequest, request: Request,
                                db: AsyncSession = Depends(get_db),
                                is_admin: bool = Depends(require_admin)):
    """把存量的明文敏感字段补加密（幂等，可反复调用直到 remaining 全为 0）。

    为什么必须有这个入口：字段加密只对「新写入」生效，本次改动之前入库的收款账号仍是
    明文，不补加密就不能声称「库里已无明文敏感字段」。做成管理端接口而不是一次性脚本：
    脚本跑在哪台机器、用的哪把密钥都无从追溯，接口走管理端鉴权 + 二次密码 + 操作日志。
    """
    if not is_admin:
        return error(ErrorCode.ADMIN_LOCKED, "管理令牌无效或已被锁定")
    pw_err = await _check_operate_password(req, db)
    if pw_err:
        return error(ErrorCode.NO_PERMISSION, pw_err)
    if not settings.SENSITIVE_FIELD_KEY:
        # 没配密钥时 encrypt_field 会降级写明文，跑一次「补加密」实际什么都没加密，
        # 还会让运维以为已经处理完——必须先挡住。
        return error(ErrorCode.SENSITIVE_DECRYPT_FAILED, "SENSITIVE_FIELD_KEY 未配置，无法补加密")
    limit = int(req.limit or 2000)
    chunk = 500
    done = {"real_name": 0, "account_name": 0, "account_no": 0}
    processed = 0
    # 分批跑：每批提交一次，中途失败已加密的部分不会回退（重跑幂等，接着往下做）。
    # 已加密的行会自动从筛选条件里消失，所以每次都从头查也在单调前进，不会原地踏步。
    while processed < limit:
        n = min(chunk, limit - processed)
        drows = (await db.execute(
            select(Distributor.id, Distributor.real_name)
            .where(Distributor.real_name.isnot(None), Distributor.real_name != "",
                   not_(Distributor.real_name.like(_ENC_PREFIX_LIKE)))
            .limit(n))).all()
        for rid, val in drows:
            await db.execute(update(Distributor).where(Distributor.id == rid)
                             .values(real_name=encrypt_field(val)))
            done["real_name"] += 1
        # withdrawals 两个字段各自判断：同一行可能一个已加密、一个还是明文（上次部分失败）
        wrows = (await db.execute(
            select(Withdrawal.id, Withdrawal.account_name, Withdrawal.account_no)
            .where(or_(
                and_(Withdrawal.account_name.isnot(None), Withdrawal.account_name != "",
                     not_(Withdrawal.account_name.like(_ENC_PREFIX_LIKE))),
                and_(Withdrawal.account_no.isnot(None), Withdrawal.account_no != "",
                     not_(Withdrawal.account_no.like(_ENC_PREFIX_LIKE)))))
            .limit(n))).all()
        for wid, wname, wno in wrows:
            vals = {}
            if wname and not is_encrypted(wname):
                vals["account_name"] = encrypt_field(wname)
                done["account_name"] += 1
            if wno and not is_encrypted(wno):
                vals["account_no"] = encrypt_field(wno)
                done["account_no"] += 1
            if vals:
                await db.execute(update(Withdrawal).where(Withdrawal.id == wid).values(**vals))
        await db.commit()
        got = len(drows) + len(wrows)
        processed += got
        if got == 0:
            break
    # 剩余明文行数：让运维看得到进度与「跑完了没」，而不是只能反复点直到不再变化。
    remaining = {
        "real_name": (await db.execute(select(func.count(Distributor.id)).where(
            Distributor.real_name.isnot(None), Distributor.real_name != "",
            not_(Distributor.real_name.like(_ENC_PREFIX_LIKE))))).scalar() or 0,
        "account_name": (await db.execute(select(func.count(Withdrawal.id)).where(
            Withdrawal.account_name.isnot(None), Withdrawal.account_name != "",
            not_(Withdrawal.account_name.like(_ENC_PREFIX_LIKE))))).scalar() or 0,
        "account_no": (await db.execute(select(func.count(Withdrawal.id)).where(
            Withdrawal.account_no.isnot(None), Withdrawal.account_no != "",
            not_(Withdrawal.account_no.like(_ENC_PREFIX_LIKE))))).scalar() or 0,
    }
    # 审计日志只记数量，绝不记内容：日志里出现明文收款账号，加密就白做了。
    await _log_operation(db, request, "crypto_backfill", "sensitive_field", None,
                         {"updated": done, "remaining": remaining})
    await db.commit()
    left = sum(int(v or 0) for v in remaining.values())
    return success({"updated": done, "processed": processed, "remaining": remaining},
                   msg="存量敏感字段已全部加密" if left == 0
                   else f"本次已处理 {processed} 行，仍有 {left} 行明文，请再次调用")


@router.get("/summary")
async def admin_summary(db: AsyncSession = Depends(get_db), is_admin: bool = Depends(require_admin)):
    if not is_admin:
        return error(ErrorCode.ADMIN_LOCKED, "管理令牌无效或已被锁定")
    auditing = (await db.execute(
        select(func.coalesce(func.sum(Withdrawal.amount), 0)).where(Withdrawal.status == "auditing"))).scalar() or 0
    pending = (await db.execute(
        select(func.coalesce(func.sum(CommissionLog.amount), 0)).where(CommissionLog.status == "pending"))).scalar() or 0
    settled = (await db.execute(
        select(func.coalesce(func.sum(CommissionLog.amount), 0)).where(CommissionLog.status == "settled"))).scalar() or 0
    auditing_count = (await db.execute(
        select(func.count(Withdrawal.id)).where(Withdrawal.status == "auditing"))).scalar() or 0
    return success({
        "auditing_withdraw_amount": float(auditing), "auditing_withdraw_count": auditing_count,
        "pending_commission": float(pending), "settled_commission": float(settled),
    })


# ==================== V1.3：排行榜与月度结算 ====================
@router.get("/rank")
async def admin_rank(month: str = Query(None, pattern=r"^\d{4}-\d{2}$"),
                     db: AsyncSession = Depends(get_db), is_admin: bool = Depends(require_admin)):
    """第二十三~二十六条：查看某月排行榜（缺省=上一自然月），附奖金总池上限。"""
    if not is_admin:
        return error(ErrorCode.ADMIN_LOCKED, "管理令牌无效或已被锁定")
    m = month or dr.last_month_key()
    return success({"month": m, "pool_cap": float(dr.rank_pool_cap()),
                    "list": await dr.get_top_ranking(db, m, limit=20)})


@router.post("/rank/settle")
async def admin_rank_settle(req: AdminRankSettleRequest, request: Request,
                            db: AsyncSession = Depends(get_db), is_admin: bool = Depends(require_admin)):
    """第二十九条：手动补结算某月阶梯差额与排行榜奖励（cron 之外的兑底；幂等只处理未结算月）。"""
    if not is_admin:
        return error(ErrorCode.ADMIN_LOCKED, "管理令牌无效或已被锁定")
    pw_err = await _check_operate_password(req, db)
    if pw_err:
        return error(ErrorCode.NO_PERMISSION, pw_err)
    m = req.month or dr.last_month_key()
    result = await dr.settle_month(db, m)
    await _log_operation(db, request, "rank_settle", "month", m, result)
    return success(result, msg=f"{m} 月度结算完成")


# ==================== V1.3：违规分级处置（第六十条） ====================
@router.get("/distributors/{dist_id}/violations")
async def admin_distributor_violations(dist_id: int, db: AsyncSession = Depends(get_db),
                                       is_admin: bool = Depends(require_admin)):
    if not is_admin:
        return error(ErrorCode.ADMIN_LOCKED, "管理令牌无效或已被锁定")
    return success({"list": await dv.get_violation_history(db, dist_id, limit=50)})


@router.post("/distributors/{dist_id}/violation")
async def admin_apply_violation(dist_id: int, req: AdminViolationRequest, request: Request,
                                db: AsyncSession = Depends(get_db), is_admin: bool = Depends(require_admin)):
    """第六十条：违规分级处置。minor警告整改/moderate冻结7天降级/severe永久清退/illegal涉嫌违法冻结。"""
    if not is_admin:
        return error(ErrorCode.ADMIN_LOCKED, "管理令牌无效或已被锁定")
    pw_err = await _check_operate_password(req, db)
    if pw_err:
        return error(ErrorCode.NO_PERMISSION, pw_err)
    dist = (await db.execute(row_lock(select(Distributor).where(
        Distributor.id == dist_id)))).scalar_one_or_none()
    if not dist:
        return error(ErrorCode.PARAM_ERROR, "推广员不存在")
    common = dict(reason=req.reason, evidence=req.evidence, handler="admin",
                  report_ticket_id=req.report_ticket_id)
    if req.level == "minor":
        rec = await dv.warn_minor(db, dist, order_id=req.order_id, **common)
    elif req.level == "moderate":
        rec = await dv.freeze_moderate(db, dist, order_id=req.order_id, **common)
    elif req.level == "severe":
        rec = await dv.terminate_severe(db, dist, order_id=req.order_id, **common)
    else:  # illegal（无 order_id 入参）
        rec = await dv.freeze_illegal(db, dist, **common)
    await _log_operation(db, request, f"violation_{req.level}", "distributor", dist_id,
                         {"reason": req.reason, "order_id": req.order_id,
                          "clawback": float(rec.clawback_amount or 0)})
    return success({"level": rec.level, "action": rec.action,
                    "clawback_amount": float(rec.clawback_amount or 0),
                    "level_before": rec.level_before, "level_after": rec.level_after,
                    "frozen_until": rec.frozen_until.strftime("%Y-%m-%d %H:%M") if rec.frozen_until else None},
                   msg="违规处置已执行")


@router.post("/distributors/{dist_id}/unfreeze")
async def admin_unfreeze(dist_id: int, req: AdminUnfreezeRequest, request: Request,
                         db: AsyncSession = Depends(get_db), is_admin: bool = Depends(require_admin)):
    """第六十条：中度冻结解冻（需期满且重考通过）；force=True 为运营强制恢复。"""
    if not is_admin:
        return error(ErrorCode.ADMIN_LOCKED, "管理令牌无效或已被锁定")
    pw_err = await _check_operate_password(req, db)
    if pw_err:
        return error(ErrorCode.NO_PERMISSION, pw_err)
    dist = (await db.execute(row_lock(select(Distributor).where(
        Distributor.id == dist_id)))).scalar_one_or_none()
    if not dist:
        return error(ErrorCode.PARAM_ERROR, "推广员不存在")
    ok, msg = await dv.unfreeze(db, dist, handler="admin", force=req.force)
    if not ok:
        return error(ErrorCode.PARAM_ERROR, msg)
    await _log_operation(db, request, "distributor_unfreeze", "distributor", dist_id, {"force": req.force})
    return success(msg=msg)


@router.post("/distributors/{dist_id}/link")
async def admin_toggle_link(dist_id: int, req: AdminLinkRequest, request: Request,
                            db: AsyncSession = Depends(get_db), is_admin: bool = Depends(require_admin)):
    """第五十条/五十八条：断链（停用专属链接与二维码，暂停新增归因）或恢复。"""
    if not is_admin:
        return error(ErrorCode.ADMIN_LOCKED, "管理令牌无效或已被锁定")
    pw_err = await _check_operate_password(req, db)
    if pw_err:
        return error(ErrorCode.NO_PERMISSION, pw_err)
    dist = (await db.execute(row_lock(select(Distributor).where(
        Distributor.id == dist_id)))).scalar_one_or_none()
    if not dist:
        return error(ErrorCode.PARAM_ERROR, "推广员不存在")
    await dv.disable_link(db, dist, req.reason, handler="admin", reenable=req.reenable)
    await _log_operation(db, request, "link_restore" if req.reenable else "link_disable",
                         "distributor", dist_id, {"reason": req.reason})
    return success({"link_disabled": 0 if req.reenable else 1},
                   msg="已恢复专属链接" if req.reenable else "已断链（停用专属链接与二维码）")


# ==================== V1.3：举报工单（第五十八条） ====================
@router.get("/reports")
async def admin_reports(status: int = Query(None), target_distributor_id: int = Query(None),
                        db: AsyncSession = Depends(get_db), is_admin: bool = Depends(require_admin)):
    if not is_admin:
        return error(ErrorCode.ADMIN_LOCKED, "管理令牌无效或已被锁定")
    return success({"list": await dc.list_report_tickets(
        db, status=status, target_distributor_id=target_distributor_id)})


@router.post("/reports/{ticket_id}/handle")
async def admin_report_handle(ticket_id: int, req: AdminReportHandleRequest, request: Request,
                              db: AsyncSession = Depends(get_db), is_admin: bool = Depends(require_admin)):
    """第五十八条：举报工单处置。respond首次响应(0->1)/handle已处置(->2)/reject驳回(->3)。"""
    if not is_admin:
        return error(ErrorCode.ADMIN_LOCKED, "管理令牌无效或已被锁定")
    pw_err = await _check_operate_password(req, db)
    if pw_err:
        return error(ErrorCode.NO_PERMISSION, pw_err)
    if req.action == "respond":
        if not await dc.respond_report_ticket(db, ticket_id):
            return error(ErrorCode.PARAM_ERROR, "工单不存在或已响应")
        msg = "已响应（24 小时内）"
    else:
        st = 2 if req.action == "handle" else 3
        ok, msg2 = await dc.handle_report_ticket(db, ticket_id, req.handle_result or "", status=st)
        if not ok:
            return error(ErrorCode.PARAM_ERROR, msg2)
        msg = "已处置并反馈举报人" if req.action == "handle" else "已驳回"
    await _log_operation(db, request, f"report_{req.action}", "report_ticket", ticket_id,
                         {"handle_result": req.handle_result})
    return success(msg=msg)


# ==================== V1.3：外部账号报备（第五十条） ====================
@router.get("/external-accounts")
async def admin_external_accounts(status: int = Query(None), distributor_id: int = Query(None),
                                  db: AsyncSession = Depends(get_db), is_admin: bool = Depends(require_admin)):
    if not is_admin:
        return error(ErrorCode.ADMIN_LOCKED, "管理令牌无效或已被锁定")
    return success({"list": await dc.list_external_accounts(
        db, distributor_id=distributor_id, status=status)})


@router.post("/external-accounts/{account_id}/review")
async def admin_external_review(account_id: int, req: AdminExternalReviewRequest, request: Request,
                                db: AsyncSession = Depends(get_db), is_admin: bool = Depends(require_admin)):
    """第五十条：外部账号报备审核（1 通过/2 拒绝）。"""
    if not is_admin:
        return error(ErrorCode.ADMIN_LOCKED, "管理令牌无效或已被锁定")
    pw_err = await _check_operate_password(req, db)
    if pw_err:
        return error(ErrorCode.NO_PERMISSION, pw_err)
    ok, msg = await dc.review_external_account(db, account_id, req.status, remark=req.remark)
    if not ok:
        return error(ErrorCode.PARAM_ERROR, msg)
    await _log_operation(db, request, "external_review", "external_account", account_id,
                         {"status": req.status, "remark": req.remark})
    return success(msg=msg)


# ==================== V1.3：敏感词库（第五十七/五十八条） ====================
@router.get("/sensitive-words")
async def admin_sensitive_words(enabled_only: bool = Query(True),
                                db: AsyncSession = Depends(get_db), is_admin: bool = Depends(require_admin)):
    if not is_admin:
        return error(ErrorCode.ADMIN_LOCKED, "管理令牌无效或已被锁定")
    return success({"list": await dc.list_sensitive_words(db, enabled_only=enabled_only)})


@router.post("/sensitive-words")
async def admin_upsert_sensitive_word(req: AdminSensitiveWordRequest, request: Request,
                                      db: AsyncSession = Depends(get_db), is_admin: bool = Depends(require_admin)):
    """第五十七/五十八条：新增或更新敏感词（word 唯一）。level 1 一级拦截/2 二级预警。"""
    if not is_admin:
        return error(ErrorCode.ADMIN_LOCKED, "管理令牌无效或已被锁定")
    pw_err = await _check_operate_password(req, db)
    if pw_err:
        return error(ErrorCode.NO_PERMISSION, pw_err)
    row = await dc.upsert_sensitive_word(db, req.word, level=req.level, category=req.category,
                                         enabled=req.enabled)
    if row is None:
        return error(ErrorCode.PARAM_ERROR, "敏感词不能为空")
    await _log_operation(db, request, "sensitive_word_upsert", "sensitive_word", row.id,
                         {"word": req.word, "level": req.level})
    return success({"id": row.id}, msg="已保存")


# ==================== V1.3：合规考试题库（第七条） ====================
@router.get("/exam/questions")
async def admin_exam_questions(db: AsyncSession = Depends(get_db), is_admin: bool = Depends(require_admin)):
    """第七条：考试题库列表（含正确答案，仅后台可见）。"""
    if not is_admin:
        return error(ErrorCode.ADMIN_LOCKED, "管理令牌无效或已被锁定")
    rows = (await db.execute(select(ExamQuestion).order_by(
        ExamQuestion.sort_order.asc(), ExamQuestion.id.asc()))).scalars().all()
    return success({"list": [{
        "id": q.id, "category": q.category, "content": q.content, "options": q.options,
        "answer": q.answer, "qtype": q.qtype or "single", "score": int(q.score or 0),
        "sort_order": int(q.sort_order or 0), "enabled": int(q.enabled or 0),
    } for q in rows]})


@router.post("/exam/questions")
async def admin_upsert_exam_question(req: AdminExamQuestionRequest, request: Request,
                                     db: AsyncSession = Depends(get_db), is_admin: bool = Depends(require_admin)):
    """第七条：新增（不传 id）或更新（传 id）考试题目。"""
    if not is_admin:
        return error(ErrorCode.ADMIN_LOCKED, "管理令牌无效或已被锁定")
    pw_err = await _check_operate_password(req, db)
    if pw_err:
        return error(ErrorCode.NO_PERMISSION, pw_err)
    if req.id:
        q = (await db.execute(select(ExamQuestion).where(
            ExamQuestion.id == req.id))).scalar_one_or_none()
        if not q:
            return error(ErrorCode.PARAM_ERROR, "题目不存在")
        q.category, q.content, q.options, q.answer = req.category, req.content, req.options, req.answer
        q.qtype, q.score, q.sort_order, q.enabled = req.qtype, req.score, req.sort_order, req.enabled
        action = "exam_question_update"
    else:
        q = ExamQuestion(category=req.category, content=req.content, options=req.options,
                         answer=req.answer, qtype=req.qtype, score=req.score,
                         sort_order=req.sort_order, enabled=req.enabled)
        db.add(q)
        action = "exam_question_create"
    await db.flush()
    await _log_operation(db, request, action, "exam_question", q.id, {"content": req.content[:50]})
    return success({"id": q.id}, msg="已保存")


# ==================== 渠道对账差错台账 ====================
# 对账只发现不改账，本组接口就是「人工处置」的那一端：看差错、标已处理、补跑对账。
@router.get("/reconcile/diffs")
async def admin_reconcile_diffs(bill_date: str = Query("", description="YYYY-MM-DD，空=全部"),
                                channel: str = Query("all"),
                                diff_type: str = Query("all"),
                                resolved: int = Query(-1, ge=-1, le=1,
                                                      description="-1全部 0未处理 1已处理"),
                                keyword: str = Query("", max_length=64,
                                                     description="按订单号或渠道流水号精确查"),
                                page: int = Query(1, ge=1),
                                page_size: int = Query(20, ge=1, le=100),
                                db: AsyncSession = Depends(get_db),
                                is_admin: bool = Depends(require_admin)):
    """对账差错列表。未处理的排在前面，并附全局未处理计数与对账链路健康位。

    健康位（enabled/channels）是必需的：差错为空既可能是「账平了」也可能是「对账根本没在跑」
    （模拟支付开关未关、渠道未配置），不给这两个标志会让管理员把后者误读成前者。"""
    if not is_admin:
        return error(ErrorCode.ADMIN_LOCKED, "管理令牌无效或已被锁定")
    stmt = select(ReconciliationDiff)
    if bill_date:
        try:
            datetime.strptime(bill_date, "%Y-%m-%d")
        except ValueError:
            return error(ErrorCode.PARAM_ERROR, "账单日格式应为 YYYY-MM-DD")
        stmt = stmt.where(ReconciliationDiff.bill_date == bill_date)
    if channel and channel != "all":
        stmt = stmt.where(ReconciliationDiff.channel == channel)
    if diff_type and diff_type != "all":
        stmt = stmt.where(ReconciliationDiff.diff_type == diff_type)
    if resolved in (0, 1):
        stmt = stmt.where(ReconciliationDiff.resolved == resolved)
    if keyword:
        kw = keyword.strip()
        stmt = stmt.where(or_(ReconciliationDiff.order_no == kw,
                              ReconciliationDiff.channel_trade_no == kw))
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar() or 0
    rows = (await db.execute(
        stmt.order_by(ReconciliationDiff.resolved.asc(), ReconciliationDiff.bill_date.desc(),
                      ReconciliationDiff.id.desc())
        .offset((page - 1) * page_size).limit(page_size))).scalars().all()
    # 待处置总览不受筛选条件影响：它是「还有多少资金差异没平」的全局事实，
    # 按类型分组便于直接判断严重度（amount_mismatch/channel_only 属资损，local_only 多为口径差）。
    type_rows = (await db.execute(
        select(ReconciliationDiff.diff_type, func.count())
        .where(ReconciliationDiff.resolved == 0)
        .group_by(ReconciliationDiff.diff_type))).all()
    items = [{
        "id": x.id, "bill_date": x.bill_date, "channel": x.channel, "diff_type": x.diff_type,
        "order_no": x.order_no, "channel_trade_no": x.channel_trade_no,
        "channel_amount": float(x.channel_amount) if x.channel_amount is not None else None,
        "local_amount": float(x.local_amount) if x.local_amount is not None else None,
        "channel_status": x.channel_status, "local_status": x.local_status,
        "detail": x.detail, "resolved": int(x.resolved or 0), "resolved_note": x.resolved_note,
        "resolved_at": x.resolved_at.strftime("%Y-%m-%d %H:%M") if x.resolved_at else None,
        "created_at": x.created_at.strftime("%Y-%m-%d %H:%M") if x.created_at else None,
    } for x in rows]
    return success({
        "list": items, "total": total, "page": page, "page_size": page_size,
        "unresolved_total": sum(int(c or 0) for _, c in type_rows),
        "unresolved_by_type": {t: int(c or 0) for t, c in type_rows},
        "reconcile": {
            "enabled": bool(settings.RECONCILE_ENABLED),
            "hour": settings.RECONCILE_HOUR, "lookback_days": settings.RECONCILE_LOOKBACK_DAYS,
            "channels": {"wechat": wechat_pay.is_configured(), "alipay": alipay.is_configured()},
        },
    })


@router.post("/reconcile/diffs/{diff_id}/resolve")
async def admin_reconcile_resolve(diff_id: int, req: AdminReconcileResolveRequest, request: Request,
                                  db: AsyncSession = Depends(get_db),
                                  is_admin: bool = Depends(require_admin)):
    """标记差错已处理（或撤销标记）。处置说明必填且进审计日志：
    对账不改账，意味着每一笔差异都是人工平的，事后必须能回答「谁、何时、怎么平的」。"""
    if not is_admin:
        return error(ErrorCode.ADMIN_LOCKED, "管理令牌无效或已被锁定")
    pw_err = await _check_operate_password(req, db)
    if pw_err:
        return error(ErrorCode.NO_PERMISSION, pw_err)
    note = (req.note or "").strip()
    if req.resolved == 1 and not note:
        return error(ErrorCode.PARAM_ERROR, "标记已处理必须填写处置说明")
    row = (await db.execute(select(ReconciliationDiff).where(
        ReconciliationDiff.id == diff_id))).scalar_one_or_none()
    if not row:
        return error(ErrorCode.PARAM_ERROR, "差错记录不存在")
    row.resolved = req.resolved
    row.resolved_note = note[:200] if note else None
    row.resolved_at = datetime.now() if req.resolved == 1 else None
    await db.flush()
    await _log_operation(db, request, "reconcile_diff_resolve", "reconcile_diff", diff_id,
                         {"resolved": req.resolved, "note": row.resolved_note,
                          "diff_type": row.diff_type, "bill_date": row.bill_date,
                          "channel": row.channel, "order_no": row.order_no})
    return success({"id": row.id, "resolved": int(row.resolved or 0)},
                   msg="已标记处理" if req.resolved == 1 else "已撤销标记")


@router.post("/reconcile/run")
async def admin_reconcile_run(req: AdminReconcileRunRequest, request: Request,
                              db: AsyncSession = Depends(get_db),
                              is_admin: bool = Depends(require_admin)):
    """手动补跑对账。传 bill_date 只对该单日，不传则按 RECONCILE_LOOKBACK_DAYS 回溯。

    互斥锁只为避开与每日 cron 重叠时的重复账单拉取（渠道对账单接口有频控）；
    对账本身幂等，即使锁失效并发跑也不会产生重复差错行或重复履约。
    不在此处 catch 异常：可预见的失败（账单未生成、渠道未配置）已由服务层转为
    bill_unavailable 差错而非抛出，能抛到这里的是真意外，走全局 500 处理并落服务器日志。
    锁必须在 finally 里释放：本接口是人工触发，不像 cron 那样可以靠 TTL 自然轮转。"""
    if not is_admin:
        return error(ErrorCode.ADMIN_LOCKED, "管理令牌无效或已被锁定")
    pw_err = await _check_operate_password(req, db)
    if pw_err:
        return error(ErrorCode.NO_PERMISSION, pw_err)
    if not settings.RECONCILE_ENABLED:
        return error(ErrorCode.PARAM_ERROR,
                     "对账未启用（RECONCILE_ENABLED=false），无渠道账单可对")
    if req.bill_date:
        try:
            datetime.strptime(req.bill_date, "%Y-%m-%d")
        except ValueError:
            return error(ErrorCode.PARAM_ERROR, "账单日格式应为 YYYY-MM-DD")
    lock_key = "lock:admin_reconcile"
    token = await redis_acquire_lock(redis_client, lock_key, 600)
    if not token:
        return error(ErrorCode.RATE_LIMIT, "对账正在执行中，请稍后再试")
    try:
        if req.bill_date:
            result = await reconcile_day(db, req.bill_date)
            # 与 cron 逐日提交口径一致：差错是资损证据，跑完就落库
            await db.commit()
        else:
            result = await reconcile_recent(db)
    finally:
        await redis_release_lock(redis_client, lock_key, token)
    await _log_operation(db, request, "reconcile_run", "reconcile", req.bill_date,
                         {"bill_date": req.bill_date or "recent",
                          "total_diffs": result.get("diffs", result.get("total_diffs", 0))})
    return success(result, msg="对账完成")


# ==================== 合规评估记录与意见留存 ====================
# 整改代码只能证明「改了」，本组接口对应的是「为什么这么改、依据哪一条、谁负责、
# 何时复核」——行政检查与纠纷中被要求出示的正是后者。
_CONCLUSION_TEXT = {"rectified": "已整改", "acceptable": "风险可接受",
                    "pending": "待整改", "rejected": "不采纳"}


def _assessment_brief(x: ComplianceAssessment) -> dict:
    """列表摘要（不含正文）：正文动辄数千字，一次拉 20 条全文会把面板拖成不可读。"""
    return {
        "id": x.id, "risk_item": x.risk_item, "topic": x.topic,
        "conclusion": x.conclusion,
        "conclusion_text": _CONCLUSION_TEXT.get(x.conclusion, x.conclusion),
        "legal_basis": x.legal_basis, "assessor": x.assessor,
        "assessed_at": x.assessed_at.strftime("%Y-%m-%d %H:%M") if x.assessed_at else None,
        "next_review_at": x.next_review_at.strftime("%Y-%m-%d") if x.next_review_at else None,
        "overdue": bool(x.next_review_at and x.next_review_at < datetime.now()),
        "status": int(x.status if x.status is not None else 1),
    }


@router.get("/compliance/assessments")
async def admin_compliance_assessments(risk_item: str = Query("", max_length=20,
                                                             description="风险项编号，空=全部"),
                                       conclusion: str = Query("all",
                                                             description="all/rectified/acceptable/pending/rejected"),
                                       status: int = Query(1, ge=0, le=1, description="1有效 0已作废"),
                                       page: int = Query(1, ge=1),
                                       page_size: int = Query(20, ge=1, le=100),
                                       db: AsyncSession = Depends(get_db),
                                       is_admin: bool = Depends(require_admin)):
    """评估记录列表。按风险项编号升序、同编号内新记录在前（追加式台账的阅读顺序）。

    附带 overdue_review（已过下次复核时点的有效记录数）：它是这张表唯一需要「催办」的信号。
    评估过期而未复核，等于该风险项处于无人负责状态，比「没有评估记录」更难被发现。"""
    if not is_admin:
        return error(ErrorCode.ADMIN_LOCKED, "管理令牌无效或已被锁定")
    stmt = select(ComplianceAssessment).where(ComplianceAssessment.status == status)
    ri = (risk_item or "").strip().upper()
    if ri:
        stmt = stmt.where(ComplianceAssessment.risk_item == ri)
    if conclusion and conclusion != "all":
        if conclusion not in _CONCLUSION_TEXT:
            return error(ErrorCode.PARAM_ERROR, "结论取值不合法")
        stmt = stmt.where(ComplianceAssessment.conclusion == conclusion)
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar() or 0
    rows = (await db.execute(
        stmt.order_by(ComplianceAssessment.risk_item.asc(), ComplianceAssessment.id.desc())
        .offset((page - 1) * page_size).limit(page_size))).scalars().all()
    # 复核到期计数不受筛选影响：它是「还有多少风险项的评估已过期」的全局事实
    overdue = (await db.execute(
        select(func.count()).select_from(ComplianceAssessment).where(and_(
            ComplianceAssessment.status == 1,
            ComplianceAssessment.next_review_at.isnot(None),
            ComplianceAssessment.next_review_at < datetime.now())))).scalar() or 0
    return success({"list": [_assessment_brief(x) for x in rows], "total": total,
                    "page": page, "page_size": page_size, "overdue_review": int(overdue),
                    "conclusions": dict(_CONCLUSION_TEXT)})


@router.get("/compliance/assessments/{assessment_id}")
async def admin_compliance_assessment_detail(assessment_id: int,
                                             db: AsyncSession = Depends(get_db),
                                             is_admin: bool = Depends(require_admin)):
    """评估记录全文（发现/措施/意见/佐证）。只读，不需二次密码：
    内容不含个人信息与资金信息，就是平台自己写的合规意见，卡住它只会让运营不愿意查。"""
    if not is_admin:
        return error(ErrorCode.ADMIN_LOCKED, "管理令牌无效或已被锁定")
    x = (await db.execute(select(ComplianceAssessment).where(
        ComplianceAssessment.id == assessment_id))).scalar_one_or_none()
    if not x:
        return error(ErrorCode.PARAM_ERROR, "评估记录不存在")
    d = _assessment_brief(x)
    d.update({"scope_desc": x.scope_desc, "finding": x.finding, "measures": x.measures,
              "opinion": x.opinion, "evidence": x.evidence,
              "created_at": x.created_at.strftime("%Y-%m-%d %H:%M") if x.created_at else None})
    return success(d)


@router.post("/compliance/assessments")
async def admin_compliance_assessment_create(req: AdminComplianceAssessmentRequest, request: Request,
                                             db: AsyncSession = Depends(get_db),
                                             is_admin: bool = Depends(require_admin)):
    """追加一条评估记录。

    只 INSERT、永不 UPDATE 旧行：可编辑的证据没有证据价值。复核就新写一行，同一 risk_item
    下以 id 最大的有效行为当前意见。本接口也因此不需要「删除/作废」入口：作废同样是改写历史，
    真有错误评估时另写一条 conclusion 相反的新记录比把旧的改掉更能说明问题。

    走二次密码 + 审计日志：写入的是对外可出示的合规结论，谁写的必须可追溯。"""
    if not is_admin:
        return error(ErrorCode.ADMIN_LOCKED, "管理令牌无效或已被锁定")
    pw_err = await _check_operate_password(req, db)
    if pw_err:
        return error(ErrorCode.NO_PERMISSION, pw_err)
    review_at = None
    if req.next_review_at:
        try:
            review_at = datetime.strptime(req.next_review_at, "%Y-%m-%d")
        except ValueError:
            return error(ErrorCode.PARAM_ERROR, "下次复核日格式应为 YYYY-MM-DD")
    row = ComplianceAssessment(
        risk_item=req.risk_item, topic=req.topic, scope_desc=req.scope_desc,
        legal_basis=req.legal_basis, finding=req.finding, conclusion=req.conclusion,
        measures=req.measures, opinion=req.opinion,
        assessor=(req.assessor or "admin"), assessed_at=datetime.now(),
        next_review_at=review_at, evidence=req.evidence, status=1)
    db.add(row)
    await db.flush()
    await _log_operation(db, request, "compliance_assessment_create", "compliance_assessment",
                         row.id, {"risk_item": row.risk_item, "topic": row.topic,
                                  "conclusion": row.conclusion, "assessor": row.assessor,
                                  "next_review_at": req.next_review_at})
    return success({"id": row.id}, msg="评估记录已追加")


@router.get("/alert/status")
async def admin_alert_status(is_admin: bool = Depends(require_admin)):
    """告警通道状态与运行统计（已接入哪些通道、触发级别、去重窗口、
    本周期收到/推送/抑制/失败各多少条）。

    只读、不需二次密码：不含个人信息与资金信息，webhook 也只回显末 8 位
    （完整地址就是机器人密钥，见 utils/alert._mask_url）。卡住它只会让运维不愿意查，
    而「通道到底通不通」恰恰是最该被随手确认的一件事。
    """
    if not is_admin:
        return error(ErrorCode.ADMIN_LOCKED, "管理令牌无效或已被锁定")
    return success(alert_svc.status())


@router.post("/alert/test")
async def admin_alert_test(req: AdminAlertTestRequest, request: Request,
                           db: AsyncSession = Depends(get_db),
                           is_admin: bool = Depends(require_admin)):
    """发一条测试告警，验证通道真的能收到。

    force=True 绕开去重：测试消息的去重键每次都一样，不 force 就会被自己上一次的窗口
    抑制，运维点了没反应，无从判断是 webhook 配错还是被去重了。
    返回体里带每个通道的成败与失败原因：只回「成功/失败」两个字，配错时根本不知道该改哪里
    （钉钉 errcode 310000 是关键词不匹配、300001 是签名错、企微 93000 是机器人已被移除，
    三者的处置方式完全不同）。
    """
    if not is_admin:
        return error(ErrorCode.ADMIN_LOCKED, "管理令牌无效或已被锁定")
    pw_err = await _check_operate_password(req, db)
    if pw_err:
        return error(ErrorCode.NO_PERMISSION, pw_err)
    if not alert_svc.alert_ready():
        return error(ErrorCode.PARAM_ERROR,
                     "告警通道未就绪：请确认 ALERT_ENABLED=true 且已配置 "
                     "ALERT_WECOM_WEBHOOK 或 ALERT_DINGTALK_WEBHOOK（均需以 http 开头），"
                     "改完需重启后端容器才生效")
    note = (req.note or "").strip()[:100]
    detail = ("这是一条由管理端手动触发的测试消息，用于验证告警通道可用，不代表系统故障。\n"
              f"触发时间 {datetime.now():%Y-%m-%d %H:%M:%S}；备注：{note or '（无）'}\n"
              "若您在群里看到本条，说明退款重试耗尽、掉单金额不符、对账差错等 ERROR 级日志"
              "能够正常推送到人。")
    res = await alert_svc.send_alert("告警通道测试消息", detail, level="INFO",
                                     key="alert:manual-test", force=True)
    await _log_operation(db, request, "alert_test", "alert_channel", None,
                         {"sent": res.get("sent"), "channels": res.get("channels"),
                          "errors": res.get("errors"), "note": note})
    if not res.get("sent"):
        # 一个通道也没发出去时仍返回业务成功码 + 明确原因，而不是抛错：测试失败本就是
        # 预期结果之一，前端要能把 errmsg 原样展示给运维——那正是他要的诊断信息。
        return success(res, msg="测试消息未能送达，请根据 errors 里的原因核对机器人配置")
    return success(res, msg=f"测试消息已发送至 {'/'.join(res.get('channels') or [])}")


# ==================== 电子发票开具台账 ====================
# 本项目不做自动开票（对接税控/服务商需纳税人资质与合同），这一组接口就是
# 「人工在税局系统开完票后回填」的那一端。台账的唯一价值是可追溯：
# 谁在何时申请了什么、平台何时开的、开的是哪一张、驳回理由是什么，缺一不可。

_INVOICE_DELIVERIES = ("email", "link", "offline")


async def _invoice_counts(db: AsyncSession) -> dict:
    """台账计数。待开具与待红冲是两张需要人主动去看的清单：
    前者超期不开是《发票管理办法》第三十五条的罚则情形，
    后者长期挂着则意味着平台账面收入与税局申报收入不符。"""
    pending = (await db.execute(select(func.count()).select_from(InvoiceRequest).where(
        InvoiceRequest.status == invoice_svc.ST_PENDING))).scalar() or 0
    red = (await db.execute(select(func.count()).select_from(InvoiceRequest).where(
        InvoiceRequest.need_red_flush == 1))).scalar() or 0
    return {"pending_total": int(pending), "red_flush_total": int(red)}


@router.get("/invoices/summary")
async def admin_invoice_summary(db: AsyncSession = Depends(get_db),
                                is_admin: bool = Depends(require_admin)):
    """台账概览（概览页与发票 tab 头部共用）。只读、不需二次密码：只有计数，无个人信息。"""
    if not is_admin:
        return error(ErrorCode.ADMIN_LOCKED, "管理令牌无效或已被锁定")
    data = await _invoice_counts(db)
    data["enabled"] = await invoice_svc.enabled(db)
    data["promise_days"] = max(int(settings.INVOICE_ISSUE_PROMISE_DAYS or 0), 1)
    data["item_name"] = (settings.INVOICE_ITEM_NAME or "").strip()
    return success(data)


@router.get("/invoices")
async def admin_invoices(status: str = Query("all", description="all/pending/issued/rejected/cancelled"),
                         need_red_flush: int = Query(-1, ge=-1, le=1,
                                                     description="-1全部 0无标记 1待红冲"),
                         keyword: str = Query("", max_length=64,
                                              description="申请单号/订单号精确，抬头/邮箱模糊"),
                         page: int = Query(1, ge=1),
                         page_size: int = Query(20, ge=1, le=100),
                         db: AsyncSession = Depends(get_db),
                         is_admin: bool = Depends(require_admin)):
    """开票申请列表。待开具的排在前面——那是唯一有时间压力的部分。

    邮箱在列表一律脱敏（与提现列表同一口径）：财务在列表阶段只需分辨是谁申请的，
    真正要把票发出去时走详情接口（二次密码门禁 + 审计），列表页不必摊开几十个人的邮箱。
    """
    if not is_admin:
        return error(ErrorCode.ADMIN_LOCKED, "管理令牌无效或已被锁定")
    stmt = select(InvoiceRequest)
    if status and status != "all":
        stmt = stmt.where(InvoiceRequest.status == status)
    if need_red_flush in (0, 1):
        stmt = stmt.where(InvoiceRequest.need_red_flush == need_red_flush)
    kw = (keyword or "").strip()
    if kw:
        # 单号类字段用等值（它们是定长随机串，模糊匹配无意义且会全表扫），
        # 抬头与邮箱用 LIKE，通配符必须转义（见 _like_escape）。
        esc = _like_escape(kw)
        stmt = stmt.where(or_(
            InvoiceRequest.apply_no == kw,
            InvoiceRequest.order_no == kw,
            InvoiceRequest.title.like(f"%{esc}%", escape="\\"),
            InvoiceRequest.email.like(f"%{esc}%", escape="\\"),
        ))
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar() or 0
    rows = (await db.execute(
        stmt.order_by((InvoiceRequest.status == invoice_svc.ST_PENDING).desc(),
                      InvoiceRequest.created_at.desc(), InvoiceRequest.id.desc())
            .offset((page - 1) * page_size).limit(page_size))).scalars().all()
    # 抬头/税号与邮箱同口径脱敏：个人抬头即真实姓名、税号可能是身份证号，
    # 列表可分页遍历全部申请；完整抬头/税号走详情接口（操作密码门禁 + 审计）。
    data = {"list": [invoice_svc.brief(r, mask_email=True, mask_pii=True) for r in rows],
            "total": total, "page": page, "page_size": page_size}
    data.update(await _invoice_counts(db))
    return success(data)


@router.get("/invoices/{invoice_id}")
async def admin_invoice_detail(invoice_id: int, request: Request,
                              db: AsyncSession = Depends(get_db),
                              is_admin: bool = Depends(require_admin),
                              x_operate_password: str = Header(default="", alias="X-Operate-Password")):
    """申请详情。邮箱明文属个人信息，配置了操作密码时必须携带二次密码（同一口径，
    与提现详情完全一致）并写审计：把票发到哪个邮箱是可被冒用的动作，必须留痕。"""
    if not is_admin:
        return error(ErrorCode.ADMIN_LOCKED, "管理令牌无效或已被锁定")
    # 密码双源不一致：原实现直接比对 .env 明文，绕过 credential_svc 的
    # 「库中 PBKDF2 哈希优先」口径——管理员在控制台改密后，旧 .env 密码对本接口
    # 永远有效。现与 _check_operate_password 同源，且改为 fail-closed：
    # 未配置操作密码时同样拒绝——本接口明文下发抬头/税号/邮箱，均为可被冒用的
    # 个人信息，门禁不能因「忘了配密码」而失效。
    if not await credential_svc.operate_password_configured(db):
        return error(ErrorCode.NO_PERMISSION,
                     "未配置操作密码，查看完整开票信息已按安全策略禁用，"
                     "请在控制台「改密码」或后端环境变量中配置操作密码后重试")
    if not await credential_svc.verify_operate_password(db, x_operate_password):
        return error(ErrorCode.NO_PERMISSION, "查看完整邮箱需要操作密码")
    inv = (await db.execute(select(InvoiceRequest).where(
        InvoiceRequest.id == invoice_id))).scalar_one_or_none()
    if not inv:
        return error(ErrorCode.PARAM_ERROR, "开票申请不存在")
    await _log_operation(db, request, "invoice_view_email", "invoice_request", inv.id)
    data = invoice_svc.detail(inv)
    order = (await db.execute(select(Order).where(Order.id == inv.order_id))).scalar_one_or_none()
    # 订单当前状态必须一并给出：台账里的 amount/status 是申请当时的快照，
    # 而「现在还能不能开」取决于订单当下是否仍是已完成的收款事实。
    # 只给快照，财务就可能给一张已退款的订单开票（为不存在的交易开票＝虚开）。
    data["order_status"] = order.status if order else "(订单不存在)"
    data["order_paid_at"] = (order.paid_at.strftime("%Y-%m-%d %H:%M")
                             if order and order.paid_at else None)
    data["can_issue"] = (inv.status == invoice_svc.ST_PENDING
                         and not inv.need_red_flush
                         and bool(order) and order.status == "completed")
    data["can_reject"] = inv.status == invoice_svc.ST_PENDING
    return success(data)


@router.post("/invoices/{invoice_id}/issue")
async def admin_invoice_issue(invoice_id: int, req: AdminInvoiceIssueRequest, request: Request,
                             db: AsyncSession = Depends(get_db),
                             is_admin: bool = Depends(require_admin)):
    """回填开具结果。写入的是对外具备法律效力的凭证信息，故走二次密码 + 审计日志。"""
    if not is_admin:
        return error(ErrorCode.ADMIN_LOCKED, "管理令牌无效或已被锁定")
    pw_err = await _check_operate_password(req, db)
    if pw_err:
        return error(ErrorCode.NO_PERMISSION, pw_err)
    inv = (await db.execute(select(InvoiceRequest).where(
        InvoiceRequest.id == invoice_id))).scalar_one_or_none()
    if not inv:
        return error(ErrorCode.PARAM_ERROR, "开票申请不存在")
    if inv.need_red_flush:
        # 这条申请对应的订单已经退款（退款钩子置的位）。此时开票就是为不存在的交易
        # 开具发票，属虚开；而标记没自动改成 cancelled 说明钩子当时失败了。
        # 硬拦 + 按 ERROR 告警（Handler 会推到人），不能只回一句「状态不对」。
        logger.error(f"[发票告警] 开具被拦：申请待红冲但订单已退款，退款联动可能已失败 "
                     f"apply_no={inv.apply_no} order={inv.order_no} status={inv.status}")
        return error(ErrorCode.INVOICE_NOT_ELIGIBLE,
                     "该申请对应订单已退款且已标记需红字冲销，不得开具；请先核实退款与冲销处置")
    if inv.status == invoice_svc.ST_ISSUED:
        # issued_at 理论上必非空，但台账可能被人工改过或早期数据不全；
        # 直接拿 None 去格式化会抛 500，而这里本该是一句可读懂的业务提示。
        when = f"{inv.issued_at:%Y-%m-%d %H:%M}" if inv.issued_at else "（开具时点未登记）"
        return error(ErrorCode.INVOICE_NOT_ELIGIBLE,
                     f"该申请已于 {when} 开具（发票号 {inv.invoice_no or '未回填'}）；"
                     "台账不允许就地改写已开具记录，如需更正请办理红字冲销后由用户重新申请")
    if inv.status != invoice_svc.ST_PENDING:
        return error(ErrorCode.INVOICE_NOT_ELIGIBLE,
                     f"当前状态为 {inv.status}，只有待开具的申请可以回填开具结果")
    order = (await db.execute(select(Order).where(Order.id == inv.order_id))).scalar_one_or_none()
    if order is None or order.status != "completed":
        # 申请时是 completed，现在不是——中间发生了退款/取消，而钩子没能把申请作废。
        # 这是「钱退了票还开着」的最后一道防线，必须拦在写入之前。
        logger.error(f"[发票告警] 开具被拦：订单当前状态 {order.status if order else '不存在'} "
                     f"但仍有待开具申请 apply_no={inv.apply_no} order={inv.order_no}")
        return error(ErrorCode.INVOICE_NOT_ELIGIBLE,
                     f"该订单当前状态为 {order.status if order else '不存在'}，已不满足开票条件"
                     "（多为已退款）；为不存在的交易开具发票属虚开，已拦截，请核实后驳回该申请")
    if req.delivery not in _INVOICE_DELIVERIES:
        return error(ErrorCode.PARAM_ERROR,
                     f"交付方式只能是 {'/'.join(_INVOICE_DELIVERIES)}")
    invoice_no = (req.invoice_no or "").strip()
    if not invoice_no:
        return error(ErrorCode.PARAM_ERROR, "发票号码必填")
    await invoice_svc.mark_issued(
        db, inv, invoice_no=invoice_no, invoice_code=(req.invoice_code or "").strip() or None,
        delivery=req.delivery, invoice_file=(req.invoice_file or "").strip() or None,
        handler="admin")
    await _log_operation(db, request, "invoice_issue", "invoice_request", inv.id,
                         {"apply_no": inv.apply_no, "order_no": inv.order_no,
                          "amount": str(inv.amount), "invoice_no": invoice_no,
                          "invoice_code": req.invoice_code, "delivery": req.delivery})
    logger.info(f"[发票] 已回填开具结果 apply_no={inv.apply_no} invoice_no={invoice_no}")
    # 响应改用脱敏 brief：原 detail() 会回传明文邮箱/抬头/税号，
    # 叠加「操作密码未配置」的旧 fail-open 时等于绕过详情接口门禁拿明文。
    # 前端登记成功后仅 toast + 刷新列表，不消费 detail 字段。
    return success({"id": inv.id,
                    "detail": invoice_svc.brief(inv, mask_email=True, mask_pii=True)},
                   msg="已登记开具结果")


@router.post("/invoices/{invoice_id}/reject")
async def admin_invoice_reject(invoice_id: int, req: AdminInvoiceRejectRequest, request: Request,
                              db: AsyncSession = Depends(get_db),
                              is_admin: bool = Depends(require_admin)):
    """驳回申请。理由必填并原样展示给用户。

    驳回不等于拒开：驳回后用户可改正抬头/税号重新提交（复用同一行）。
    但若理由含糊（「不符合条件」），用户看不出该改什么，就只能反复提交或去 12366 投诉，
    而拒开发票是《发票管理办法》第三十五条的罚则情形——所以理由长度在 schema 层就卡住。
    """
    if not is_admin:
        return error(ErrorCode.ADMIN_LOCKED, "管理令牌无效或已被锁定")
    pw_err = await _check_operate_password(req, db)
    if pw_err:
        return error(ErrorCode.NO_PERMISSION, pw_err)
    inv = (await db.execute(select(InvoiceRequest).where(
        InvoiceRequest.id == invoice_id))).scalar_one_or_none()
    if not inv:
        return error(ErrorCode.PARAM_ERROR, "开票申请不存在")
    if inv.status != invoice_svc.ST_PENDING:
        return error(ErrorCode.INVOICE_NOT_ELIGIBLE,
                     f"当前状态为 {inv.status}，只有待开具的申请可以驳回")
    reason = (req.reason or "").strip()
    inv.status = invoice_svc.ST_REJECTED
    inv.reject_reason = reason
    inv.handler = "admin"
    await db.flush()
    await _log_operation(db, request, "invoice_reject", "invoice_request", inv.id,
                         {"apply_no": inv.apply_no, "order_no": inv.order_no,
                          "amount": str(inv.amount), "reason": reason})
    logger.info(f"[发票] 申请已驳回 apply_no={inv.apply_no} reason={reason}")
    # 与 issue 接口同口径：响应改用脱敏 brief，不回传明文个人信息。
    return success({"id": inv.id,
                    "detail": invoice_svc.brief(inv, mask_email=True, mask_pii=True)},
                   msg="已驳回，用户可修改后重新提交")
