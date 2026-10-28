import base64
import hashlib
import hmac
import logging
import re
import secrets
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Request, Response, Query
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from app.core.database import get_db
from app.core.models import User
from app.core.schemas import LoginRequest, RefreshRequest, WechatLoginRequest, BindInviteRequest, SyncWechatProfileRequest, EmailRegisterRequest, EmailLoginRequest, PasswordResetRequest, SendEmailCodeRequest
from app.core.auth import (create_jwt_token, redis_client, get_current_user, set_auth_cookie,
                           clear_auth_cookie, AUTH_COOKIE_NAME, add_to_blacklist, decode_jwt_token,
                           mark_device_code_released, is_device_code_released)
from app.core.api.common import success, error, ErrorCode, get_client_ip, redis_rate_limit
from app.core.services.distribution import bind_inviter
from app.core.services import identity as identity_svc
from app.core.services import distribution_compliance as compliance_svc
from app.core.utils.wechat_oauth import build_authorize_url, code2session, oauth_configured, fetch_userinfo
from app.config import settings

# 邮件发送为可选依赖：未接入邮件服务时（HAS_EMAIL=False）不阻断流程，
# 非生产环境由 send-code 接口回显 dev_code 以便联调，生产环境必须真正发出。
try:
    from app.core.email import send_verification_code  # type: ignore
    HAS_EMAIL = True
except Exception:
    send_verification_code = None
    HAS_EMAIL = False

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["认证"])

# 同 IP 注册上限（10 分钟窗口）
_REGISTER_LIMIT = 5
_REGISTER_WINDOW = 600
# 登录/刷新上限（10 分钟窗口）：设备码是外部浏览器下的唯一凭证，
# 不限流即可离线穷举爆破，命中他人设备码就直接接管其账号
_LOGIN_LIMIT = 20
_LOGIN_WINDOW = 600
# M1：设备码格式强校验——h5- + 至少 20 位字母数字（主路径为 CSPRNG 生成的 32 位 hex，
# 存量弱熵用户设备码为 base36 亦可匹配），总长不超过 VARCHAR(64)。
# 拦截 "h5-1" 之类的低熵值，封堵对设备码空间的离线穷举。
_DEVICE_CODE_RE = re.compile(r"^h5-[A-Za-z0-9]{20,61}$")
# 邮箱格式校验：仅做基本形状约束，不追求 RFC 全覆盖
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$")
# 邀请码绑定上限（10 分钟窗口）：与 /login、/refresh 同一理由——凭证类接口不限流即可离线穷举。
# 邀请码为「X + HHMMSS + 5 位 hex」（见 services.distribution.gen_invite_code，截断到 12 位），
# 其中时间段在推广员注册时刻已知时可大幅收窄，剩余空间仅 16^5；每次尝试都是一次 DB 查询，
# 不限流同时也是查询放大器。绑定成功后永久生效且不可更改（第三十七条），故枚举成功即不可逆。
_BIND_INVITE_LIMIT = 20
_BIND_INVITE_WINDOW = 600


def _b64(raw: str) -> str:
    return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")


# 微信 state 上限 128 字节，签名固定占 "." + 24 位 hex = 25 字节，payload 预算 103
_STATE_MAX = 128
_SIG_LEN = 25
_STATE_PAYLOAD_BUDGET = _STATE_MAX - _SIG_LEN
# 前端 buildState() 产出的已经是 base64url（无填充），本身就落在这个字符集里
_URLSAFE_STATE = re.compile(r"^[A-Za-z0-9_.\-]+$")
# P1 修复（登录 CSRF）：state 浏览器绑定的 Cookie 名与 Redis key 前缀
_WX_NONCE_COOKIE = "wx_onc"
# H1 修复（同步微信资料 CSRF）：与登录用独立 Cookie 名，避免两条流程的 nonce 互相覆盖/误消费
_SYNC_NONCE_COOKIE = "wx_sync_onc"

def _state_key(signed: str) -> str:
    return "wx_state:" + hashlib.sha256(signed.encode()).hexdigest()


def _state_payload(raw: str) -> str:
    """把原始 state 变成可放进 URL 的 payload。

    已是 URL-safe 字符集的原样保留：前端传来的就是 base64url，再套一层 base64
    会让长度凭空膨胀 33%，直接把 state 顶出微信的 128 字节上限。"""
    s = raw or ""
    if s and _URLSAFE_STATE.match(s):
        return s
    return _b64(s)


def sign_state(raw: str) -> str:
    """L12：state 加 HMAC 签名，防篡改邀请码/回跳路径。

    超长时只能裁 payload，绝不能裁签名：原实现由 build_authorize_url 把签好的整串
    截到 128 字符，等于把 HMAC 尾巴砍掉，回跳后 verify_state 必然失败；而 L12 之后
    state 校验是登录硬前置，微信内用户会直接被挡在门外（探针实测 7 个真实场景挂 3 个，
    例如 #/report?order_no=... 这类带参数的分享链接）。
    裁掉 payload 尾部最多让前端 parseState 解不出 p/r：回跳后落在首页、邀请码丢失
    （邀请码前端另有 7 天 localStorage 兜底），登录本身不受影响。"""
    payload = _state_payload(raw)
    if len(payload) > _STATE_PAYLOAD_BUDGET:
        logger.warning(f"授权 state 超长，已裁剪 payload: {len(payload)} -> {_STATE_PAYLOAD_BUDGET}")
        payload = payload[:_STATE_PAYLOAD_BUDGET]
    sig = hmac.new(settings.JWT_SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()[:24]
    return f"{payload}.{sig}"


def verify_state(signed: str) -> Optional[str]:
    """校验 state 签名。返回 None 表示验签失败（调用方据此拒绝登录）；
    返回被签名的 payload 字符串表示签名有效、state 确由本服务签发。

    刻意不对 payload 做 base64 解码：sign_state 只在原文含非 URL-safe 字符时
    才编码一次，事后无法可靠区分「原文本来就是 base64url」与「我们编码过一次」，
    强行解码会把前端传来的 base64url state 解成 JSON（往返不再恒等），
    而超长被裁剪过的 payload 又会解出不完整的 UTF-8 序列直接抛异常。
    原实现把「签名有效但解码失败」和「签名被篡改」一并归到 except 里返回 None，
    等于用户只是分享了一个带参数的长链接，回跳后就被判定为授权校验失败、
    彻底登录不了（L12 之后 state 校验是登录硬前置）。
    安全边界只由 HMAC 比对决定；透传内容由前端 parseState 自行解析，
    解不开会落到首页，邀请码另有 7 天 localStorage 兜底。
    """
    try:
        payload, sig = signed.rsplit(".", 1)
    except Exception:
        return None
    try:
        expect = hmac.new(settings.JWT_SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()[:24]
    except Exception:
        return None
    if not hmac.compare_digest(sig, expect):
        return None
    return payload


async def _register_allowed(request: Request) -> bool:
    """M3：原子限流（Lua incr+expire），替代先 get 后 incr 的竞态写法"""
    ip = get_client_ip(request)
    return await redis_rate_limit(redis_client, f"register_limit:{ip}", _REGISTER_LIMIT, _REGISTER_WINDOW)


async def _issue_token(db: AsyncSession, user: User, invite_code):
    if not user.inviter_id and invite_code:
        await bind_inviter(db, user, invite_code)
    token, _ = create_jwt_token(user.id)
    return token



# ============ 邮箱账号密码：pbkdf2_sha256（标准库实现，避免引入新依赖） ============
# 【安全审计修复】迭代次数 12 万 → 60 万（OWASP 对 PBKDF2-HMAC-SHA256 的现行下限）：
# 拖库后的离线爆破成本与迭代次数成正比，12 万在当代 GPU 上已不够看。
# 兼容说明：哈希串里写死了当次迭代数，verify 按串内值派生，存量密码无需重置；
# 单次登录派生约 0.2~0.4s（hashlib 走 C 实现），登录接口已有 IP 级限流兜底 CPU 面。
_PBKDF2_ITERATIONS = 600000


def _hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                             salt.encode("utf-8"), _PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${_PBKDF2_ITERATIONS}${salt}${dk.hex()}"


def _verify_password(password: str, stored: str) -> bool:
    """恒定时间比较，避免时序侧信道"""
    try:
        algo, iters, salt, hexdigest = (stored or "").split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                 salt.encode("utf-8"), int(iters))
        return hmac.compare_digest(dk.hex(), hexdigest)
    except Exception:
        return False


@router.get("/authorize-url")
async def authorize_url(request: Request, state: str = Query("", max_length=256), resp: Response = None):
    """返回微信静默授权链接；L12：state 经后端签名。
    防登录 CSRF（P1 修复）：签名只能证明 state 由本服务签发，不能证明是「当前用户浏览器」
    发起的——攻击者可自己调本接口拿到合法签名的 state，拼上自己微信的 code 诱骗受害者
    打开，受害者即被登进攻击者账号。修复为 OAuth 标准的浏览器绑定（double-submit）：
    下发授权链接时生成一次性 nonce 同时写入 Redis（state→nonce）与发起方 Cookie，
    回跳登录时两者必须匹配，且登录成功即消费（DEL）防重放。"""
    if not oauth_configured():
        return error(ErrorCode.PARAM_ERROR, "微信网页授权未配置")
    # L1 修复：匿名端点此前无限流，每次调用都写一个一次性 Redis 键（state 可任意变化），
    # 构成写入放大器。与 wechat-login 同口径加 IP 级限流（30 次/分钟，真人足够）。
    if not await redis_rate_limit(
            redis_client, f"rate:authurl_ip:{get_client_ip(request)}", 30, 60):
        return error(ErrorCode.RATE_LIMIT, "操作过于频繁，请稍后再试")
    signed = sign_state(state)
    nonce = secrets.token_urlsafe(16)
    st_key = _state_key(signed)
    try:
        # EXPIRE 后（10 分钟）未完成登录的授权链接自然作废，需重新从入口进入
        await redis_client.setex(st_key, 600, nonce)
    except Exception:
        logger.exception("微信授权 state 登记失败（Redis 不可用），fail-closed 拒绝下发")
        return error(ErrorCode.PARAM_ERROR, "服务繁忙，请稍后重试")
    # httpOnly + SameSite=Lax：仅本站 /api/auth 路径携带；微信跳转不影响第一方 Cookie
    resp.set_cookie(_WX_NONCE_COOKIE, nonce, max_age=600, httponly=True,
                    samesite="lax", path="/api/auth")
    url = build_authorize_url(signed)
    if not url:
        return error(ErrorCode.PARAM_ERROR, "授权回跳域名未配置")
    return success({"authorize_url": url})


@router.post("/wechat-login")
async def wechat_login(req: WechatLoginRequest, request: Request, db: AsyncSession = Depends(get_db)):
    """微信静默授权登录"""
    # P3 修复：本接口会触发对微信 code2session 的外部调用（放大器），此前无任何限流。
    # IP 级 30 次/分钟：正常单用户一次登录只打 1-2 次，阈值宽松不影响真人。
    allowed = await redis_rate_limit(
        redis_client, f"rate:wxlogin_ip:{get_client_ip(request)}", 30, 60)
    if not allowed:
        return error(ErrorCode.RATE_LIMIT, "操作过于频繁，请稍后再试")
    # L12 + 安全修复：state 必须存在且签名有效，否则不予登录。
    # 原实现验签失败只打 warning 仍继续登录，构成 OAuth 登录 CSRF：
    # 攻击者用自己的微信 code 拼出回跳链接诱骗受害者打开，受害者浏览器就会登录到
    # 攻击者账号，其随后填写的出生信息档案、支付与报告全部落入攻击者账号可被读取。
    # 正常流程必然携带签名 state（authorize-url 下发 → 微信原样回传），强制校验不影响真实用户。
    if not req.state:
        return error(ErrorCode.PARAM_ERROR, "微信授权已失效，请关闭页面重新从入口进入")
    if verify_state(req.state) is None:
        logger.warning(f"微信登录 state 签名校验失败，已拦截: {req.state[:40]}")
        return error(ErrorCode.PARAM_ERROR, "微信授权校验失败，请关闭页面重新从入口进入")
    # P1 修复：state 必须与发起授权的浏览器绑定（authorize-url 下发的 Cookie nonce 与
    # Redis 登记值匹配），封堵「攻击者的 state + 攻击者的 code」登录 CSRF。
    # Redis 不可用或登记过期时一律拒绝（fail-closed）：宁可让用户重走一次授权，
    # 也不接受无法证明归属的 state。
    st_key = _state_key(req.state)
    try:
        stored = await redis_client.get(st_key)
    except Exception:
        stored = None
    if isinstance(stored, bytes):
        stored = stored.decode()
    cookie_nonce = request.cookies.get(_WX_NONCE_COOKIE)
    if not stored or not cookie_nonce or not hmac.compare_digest(cookie_nonce, stored):
        logger.warning("微信登录 state 浏览器绑定校验失败，已拦截（nonce 不匹配/过期）")
        return error(ErrorCode.PARAM_ERROR, "微信授权已失效，请关闭页面重新从入口进入")
    session = await code2session(req.code.strip())
    if not session:
        # T20：code 一次性，刷新回调页会失败，给出明确可恢复提示
        return error(ErrorCode.PARAM_ERROR, "微信授权已失效，请关闭页面重新从入口进入")
    openid = session["openid"]
    unionid = session.get("unionid") or None
    user = (await db.execute(select(User).where(User.oa_openid == openid))).scalar_one_or_none()
    is_new = False
    if not user and unionid:
        user = (await db.execute(select(User).where(User.unionid == unionid))).scalar_one_or_none()
        if user:
            user.oa_openid = openid
    # 双向定位（属主决策）：微信标识查无账号、但请求携带已注册设备码，且该设备账号
    # 尚未绑任何微信标识时，判为同一人——把微信标识并到设备账号上，而不是新建行。
    # 不并的后果是同一人两个 user_id：订单/会员/开票劈成两半，财务永远对不上。
    # 设备账号已绑其他微信（两人共用一台设备）时不并，保持账号分离。
    device_code = (req.device_code or "").strip()
    # 【安全审计修复 M8】已释放的设备码不得再参与「双向定位/反向补绑」：
    # 它是已被用户主动作废的凭证，重新挂到账号上等于把处置撤销。
    device_ok = bool(_DEVICE_CODE_RE.match(device_code)) \
        and not await is_device_code_released(device_code)
    if not user and device_ok:
        device_user = (await db.execute(select(User).where(
            User.device_code == device_code, User.status == 1))).scalar_one_or_none()
        if device_user and not device_user.oa_openid and not device_user.mp_openid:
            user = device_user
            user.oa_openid = openid
            if unionid and not user.unionid:
                user.unionid = unionid
            logger.info(f"[双向定位] 微信标识并到设备账号 uid={user.id}（避免一人多号劈裂订单/开票）")
    if not user:
        if not await _register_allowed(request):
            return error(ErrorCode.RATE_LIMIT, "操作过于频繁，请稍后再试")
        user = User(oa_openid=openid, unionid=unionid)
        # 同一 openid 的并发回调（回跳页刷新/双击）会同时查不到用户并各自 INSERT，
        # oa_openid 唯一约束让后到者抛 IntegrityError → 500，用户只看到「登录失败」。
        # 用 SAVEPOINT 包住 INSERT：撞约束就改读已存在的那条，且不污染外层事务
        # （否则 get_db 退出时的 commit 会连带失败，本次请求彻底发不出 token）。
        # 与 services/membership.py 的 N3、插件的报告创建同一套路。
        try:
            async with db.begin_nested():
                db.add(user)
            is_new = True
        except IntegrityError:
            user = (await db.execute(
                select(User).where(User.oa_openid == openid))).scalar_one_or_none()
            if not user:
                logger.error(f"微信登录并发建号后仍读不到用户 openid前8位={openid[:8]}")
                return error(ErrorCode.PARAM_ERROR, "微信授权已失效，请关闭页面重新从入口进入")
            is_new = False
    token = await _issue_token(db, user, req.invite_code)
    # 双向定位：反向补绑设备码（微信账号无设备码且该码未被占用）+ 写身份台账 +
    # 刷新 users.last_login_*（订单创建时的快照源）。
    if device_ok and not user.device_code:
        occupied = (await db.execute(select(User.id).where(
            User.device_code == device_code))).scalar_one_or_none()
        if not occupied:
            user.device_code = device_code
    user.last_login_type = identity_svc.ID_OA_OPENID
    user.last_login_value = openid
    await identity_svc.record_login_identity(db, user.id, identity_svc.ID_OA_OPENID, openid)
    if unionid:
        await identity_svc.record_login_identity(db, user.id, identity_svc.ID_UNIONID, unionid)
    if user.device_code:
        await identity_svc.record_login_identity(db, user.id, identity_svc.ID_DEVICE, user.device_code)
    await db.flush()
    # P1 修复：登录成功即消费 state（一次性），防止同一条授权链接被重放
    try:
        await redis_client.delete(st_key)
    except Exception:
        pass
    # M4：登录成功仅通过 httpOnly Cookie 下发会话，响应体不再回传 token（防 XSS 从响应体窃取）
    resp = JSONResponse(content=success(
        {"user_id": user.id, "is_new": is_new, "auth_type": "wechat"}))
    set_auth_cookie(resp, token, request)
    resp.delete_cookie(_WX_NONCE_COOKIE, path="/api/auth")
    return resp


@router.post("/login")
async def login(req: LoginRequest, request: Request, db: AsyncSession = Depends(get_db)):
    """兜底登录（外部浏览器）：设备码查找或创建。M2：记录首次登录 IP 用于异常审计"""
    device_code = req.code.strip()
    # M1：设备码格式强校验（h5- + ≥20 位字母数字），封堵低熵值穷举
    if not _DEVICE_CODE_RE.match(device_code):
        return error(ErrorCode.PARAM_ERROR, "设备码格式错误")
    # 命中已存在用户也必须限流：原实现只对“新建用户”走 _register_allowed，
    # 意味着攻击者可无限次穷举他人设备码，一旦命中即拿到其 token 完成账号接管。
    if not await redis_rate_limit(redis_client, f"login_limit:{get_client_ip(request)}",
                                  _LOGIN_LIMIT, _LOGIN_WINDOW):
        return error(ErrorCode.RATE_LIMIT, "操作过于频繁，请稍后再试")
    # M8 的另一半：已解绑的设备码必须在这里就明确拒掉。_release_device_code 会把
    # users.device_code 置空，缺了这道校验，旧码会落到下面「查无用户 → 新建账号」分支，
    # 静默生成一个空账号（用户视角：订单/会员/余额全没了），与 /device/release 的承诺相反。
    # /refresh 与微信绑定路径都查了，设备码主入口不能漏。
    if await is_device_code_released(device_code):
        return error(ErrorCode.NOT_LOGIN, "该设备的登录凭证已失效，请用邮箱或微信登录后重新绑定")
    user = (await db.execute(
        select(User).where(User.device_code == device_code, User.status == 1))).scalar_one_or_none()
    if user:
        # 双向定位：写台账 + 刷新最近登录标识（订单快照源）
        user.last_login_type = identity_svc.ID_DEVICE
        user.last_login_value = device_code
        await identity_svc.record_login_identity(db, user.id, identity_svc.ID_DEVICE, device_code)
        token = await _issue_token(db, user, req.invite_code)
        resp = JSONResponse(content=success(
            {"user_id": user.id, "is_new": False, "auth_type": "device"}))
        set_auth_cookie(resp, token, request)
        return resp
    if not await _register_allowed(request):
        return error(ErrorCode.RATE_LIMIT, "操作过于频繁，请稍后再试")
    user = User(device_code=device_code,
                last_login_type=identity_svc.ID_DEVICE, last_login_value=device_code)
    # L2 修复：同一设备码的并发首登（双击/多标签/重试）会同时查不到用户并各自 INSERT，
    # uk_device_code 唯一约束让后到者抛 IntegrityError → 500。用 SAVEPOINT 包住 INSERT，
    # 撞约束就改读已存在的那条（与上面微信路径同一套路），不污染外层事务。
    is_new = True
    try:
        async with db.begin_nested():
            db.add(user)
    except IntegrityError:
        user = (await db.execute(select(User).where(
            User.device_code == device_code, User.status == 1))).scalar_one_or_none()
        if not user:
            logger.error(f"设备码登录并发建号后仍读不到用户 code前8位={device_code[:8]}")
            return error(ErrorCode.PARAM_ERROR, "登录失败，请重试")
        is_new = False
    await identity_svc.record_login_identity(db, user.id, identity_svc.ID_DEVICE, device_code)
    token = await _issue_token(db, user, req.invite_code)
    resp = JSONResponse(content=success(
        {"user_id": user.id, "is_new": is_new, "auth_type": "device"}))
    set_auth_cookie(resp, token, request)
    return resp


@router.post("/refresh")
async def refresh_token(req: RefreshRequest, request: Request, db: AsyncSession = Depends(get_db)):
    """刷新 token：设备码即凭证，必须限流且校验格式，否则可被穷举爆破"""
    device_code = req.code.strip()
    # M1：设备码格式强校验，与 /login 同口径
    if not _DEVICE_CODE_RE.match(device_code):
        return error(ErrorCode.PARAM_ERROR, "设备码格式错误")
    if not await redis_rate_limit(redis_client, f"refresh_limit:{get_client_ip(request)}",
                                  _LOGIN_LIMIT, _LOGIN_WINDOW):
        return error(ErrorCode.RATE_LIMIT, "操作过于频繁，请稍后再试")
    # 【安全审计修复 M8】与 /login 同口径：已释放的设备码不再能换会话
    if await is_device_code_released(device_code):
        return error(ErrorCode.NOT_LOGIN, "该设备的登录凭证已失效，请重新进入页面")
    user = (await db.execute(
        select(User).where(User.device_code == device_code, User.status == 1))).scalar_one_or_none()
    if not user:
        return error(ErrorCode.NOT_LOGIN, "用户不存在")
    # 双向定位：refresh 也是凭设备标识换会话，同样刷新台账与最近登录标识，
    # 保证后续下单快照与当前活跃会话的登录维度一致。
    user.last_login_type = identity_svc.ID_DEVICE
    user.last_login_value = device_code
    await identity_svc.record_login_identity(db, user.id, identity_svc.ID_DEVICE, device_code)
    token, _ = create_jwt_token(user.id)
    resp = JSONResponse(content=success())
    set_auth_cookie(resp, token, request)
    return resp


async def _revoke_token(user_id: int, token: str) -> bool:
    """拉黑单个 token，返回是否撤销成功。解析失败/无 jti 均视为撤销失败。"""
    try:
        payload = decode_jwt_token(token)
    except Exception:
        logger.warning("退出登录解析 token 失败，无法撤销 uid=%s", user_id, exc_info=True)
        return False
    jti = payload.get("jti")
    if not jti:
        logger.warning("退出登录 token 缺少 jti，无法定位撤销 uid=%s", user_id)
        return False
    exp = payload.get("exp")
    remaining = max(1, int(exp - datetime.now(timezone.utc).timestamp())) if exp \
        else 7 * 24 * 3600
    return await add_to_blacklist(user_id, jti, remaining)


@router.post("/logout")
async def logout(request: Request,
                 reset_device: bool = False,
                 credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer(auto_error=False)),
                 db: AsyncSession = Depends(get_db),
                 user: User = Depends(get_current_user)):
    """M4：退出登录——拉黑当前 token（不影响其他设备）+ 清除 httpOnly Cookie。
    R2 回归修复：原实现误用用户级黑名单（会把该用户全部设备一并登出）；
    且 Cookie 会话（无 Bearer 头）时读不到 token、什么都没拉黑。现从请求头或 Cookie 取当前 token。

    【安全审计修复 M7】撤销失败必须可感知：原实现 `except Exception: pass` 后一律回
    「已退出登录」。共享设备上用户据此认为会话已失效，实际 token 仍可用到自然过期，
    服务端日志连一条错误都没有。现如实回传 revoked=false 与明确文案。

    【安全审计修复（双凭证）】Bearer 头与 httpOnly Cookie 可能同时存在且是**两个不同的
    token**（例如 H5 走 Cookie、前端又用旧 token 打了 Authorization）。原实现二选一，
    只撤销其中一个，另一个在登出后依然有效。现两个都撤销。
    """
    tokens: list[str] = []
    if credentials is not None and credentials.credentials:
        tokens.append(credentials.credentials)
    cookie_token = request.cookies.get(AUTH_COOKIE_NAME)
    if cookie_token and cookie_token not in tokens:
        tokens.append(cookie_token)

    revoked = True
    if not tokens:
        # 无任何凭证：本次请求本身靠 Cookie/头才通过鉴权，走到这里说明两者都没有，
        # 也就无从撤销——不能回报「已退出登录」。
        revoked = False
        logger.warning("退出登录未携带任何凭证，无可撤销的 token uid=%s", user.id)
    for t in tokens:
        revoked = await _revoke_token(user.id, t) and revoked

    device_released = False
    if reset_device:
        device_released, _msg = await _release_device_code(user, db)
        # 解绑是持久变更，必须显式提交：依赖的 get_db 不自动 commit，
        # 不提交则设备码解绑随请求结束回滚——用户以为已失效，实际旧码仍指向账号。
        await db.commit()

    resp = JSONResponse(content=success(
        {"revoked": revoked, "device_released": device_released},
        "已退出登录" if revoked else
        "已清除本地登录态，但服务端会话撤销失败，该登录凭证在有效期内仍可使用，请勿在公共设备停留并稍后重试"))
    clear_auth_cookie(resp)
    return resp


async def _release_device_code(user: User, db: AsyncSession) -> tuple[bool, str]:
    """解绑当前账号的设备码（设备登录凭证立即失效）。

    【安全审计修复 M8】设备码是外部浏览器下的长期凭证（无口令、无过期、登出不影响）。
    此前没有任何处置手段：退出登录后该码仍指向原账号，任何人打开页面即进入；
    若只把 users.device_code 置空，旧码又会走 /login 的「查无用户 → 新建账号」
    分支，静默生成一个全新空账号（用户视角：订单/会员/余额全部消失）。
    故解绑前先登记「该码已释放」（失败则不解绑，fail-closed），登录链路据此明确拒绝。

    台账 user_identities 保留原码（与订单/退款不删同一口径），保证事后可审计
    「这个设备码曾属于哪个账号」。
    """
    code = (user.device_code or "").strip()
    if not code:
        return False, "当前账号未绑定设备登录凭证"
    # 释放后设备码即失效，必须保证账号还有别的入口可进：纯设备码账号（无邮箱密码、
    # 无微信标识）一旦释放就再也回不来——释放等于把账号判了无期，而用户点按钮时
    # 未必意识到这一点。真要彻底作废账号，走 /user/delete 注销（有归档与台账留痕）。
    # 注：本仓库 web/ 是 PC 站，走邮箱登录（/api/auth/email/login），不使用设备码，
    # 因此这条校验只作用于「只有设备码的游客账号」。
    has_other_credential = bool(user.password_hash) or bool(
        user.oa_openid or user.mp_openid or user.unionid)
    if not has_other_credential:
        return False, "请先绑定邮箱或微信后再解除设备登录凭证（解除后该凭证失效；如需彻底作废账号请走注销）"
    if not await mark_device_code_released(code):
        return False, "服务繁忙，设备登录凭证释放失败，请稍后重试"
    user.device_code = None
    # 「最近登录标识」属个人信息：解绑该凭证后不再保留它的明文指向。
    if user.last_login_type == identity_svc.ID_DEVICE:
        user.last_login_type = None
        user.last_login_value = None
    await db.flush()
    return True, "设备登录凭证已失效"


@router.post("/device/release")
async def release_device(request: Request,
                         db: AsyncSession = Depends(get_db),
                         user: User = Depends(get_current_user)):
    """解绑当前账号的设备登录凭证（设备码立即失效，不可再用于登录）。

    适用场景：设备转手/共用后主动失效旧凭证。凭证失效后该设备再登录会收到明确提示，
    不会静默新建一个空账号；原账号请通过微信登录进入（同一人两条登录路径互为兜底）。
    """
    if not await redis_rate_limit(
            redis_client, f"rate:device_release:{user.id}", 5, 60):
        return error(ErrorCode.RATE_LIMIT, "操作过于频繁，请稍后再试")
    ok, msg = await _release_device_code(user, db)
    await db.commit()
    return success({"released": ok}, msg)


@router.post("/bind-invite")
async def bind_invite_api(req: BindInviteRequest, request: Request,
                          db: AsyncSession = Depends(get_db),
                          user: User = Depends(get_current_user)):
    code = (req.invite_code or "").strip()
    if not code:
        return error(ErrorCode.PARAM_ERROR, "邀请码不能为空")
    if user.inviter_id:
        return success({"bound": False, "msg": "已绑定邀请关系，不可更改"})
    # 已绑定者上面已短路返回，走到这里的都是「还能改绑定关系」的账号，正是枚举的目标面。
    if not await redis_rate_limit(
            redis_client, f"bind_invite_limit:{get_client_ip(request)}",
            _BIND_INVITE_LIMIT, _BIND_INVITE_WINDOW):
        return error(ErrorCode.RATE_LIMIT, "操作过于频繁，请稍后再试")
    ok = await bind_inviter(db, user, code)
    await db.flush()
    return success({"bound": ok})


# ==================== 微信头像/昵称同步（snsapi_userinfo 显式授权） ====================
# 登录主路径是 snsapi_base 静默授权，拿不到昵称头像（微信政策：静默授权仅 openid）。
# 同步必须由用户显式发起：下发 snsapi_userinfo 授权链接 → 微信弹确认框 → 回跳 code →
# 本组接口换 access_token 拉取 nickname/headimgurl。个保法口径：单独同意、按需采集。
_SYNC_STATE_MARKER = "syncprofile"


@router.get("/profile-authorize-url")
async def profile_authorize_url(request: Request, user: User = Depends(get_current_user),
                                resp: Response = None):
    """下发「同步微信头像昵称」的 snsapi_userinfo 授权链接（需登录）。

    H1 修复（同步微信资料 CSRF）：与登录流程同款 double-submit 浏览器绑定——
    下发链接时生成一次性 nonce 同时写 Redis（state→nonce）与发起方 Cookie，回跳同步时
    两者必须匹配且成功即消费。此前 state 是全站恒定值、不登记 nonce，攻击者可用自己的
    code 诱导受害者打开链接，把攻击者微信绑到受害者账号，再走微信登录完成账号接管。"""
    if not oauth_configured():
        return error(ErrorCode.PARAM_ERROR, "微信网页授权未配置")
    # 需登录态才能发起，攻击面小于匿名 authorize-url，但仍加用户级限流防 nonce 写入放大
    if not await redis_rate_limit(
            redis_client, f"rate:profile_authurl:{user.id}", 30, 60):
        return error(ErrorCode.RATE_LIMIT, "操作过于频繁，请稍后再试")
    signed = sign_state(_SYNC_STATE_MARKER)
    nonce = secrets.token_urlsafe(16)
    st_key = _state_key(signed)
    try:
        await redis_client.setex(st_key, 600, nonce)
    except Exception:
        logger.exception("同步微信资料 state 登记失败（Redis 不可用），fail-closed 拒绝下发")
        return error(ErrorCode.PARAM_ERROR, "服务繁忙，请稍后重试")
    url = build_authorize_url(signed, scope="snsapi_userinfo")
    if not url:
        return error(ErrorCode.PARAM_ERROR, "授权回跳域名未配置")
    resp.set_cookie(_SYNC_NONCE_COOKIE, nonce, max_age=600, httponly=True,
                    samesite="lax", path="/api/auth")
    return success({"authorize_url": url})


@router.post("/sync-wechat-profile")
async def sync_wechat_profile(req: SyncWechatProfileRequest, request: Request,
                              db: AsyncSession = Depends(get_db),
                              user: User = Depends(get_current_user)):
    """用 snsapi_userinfo 回跳 code 同步微信昵称/头像到当前账号。

    安全边界：
    · code 一次性且 scope 必须含 snsapi_userinfo（静默授权的 code 换不到 userinfo）；
    · openid 必须与当前账号已绑定的 oa_openid 一致——攻击者拿自己的 code 也同步不到别人账号；
    · 设备码账号（无 oa_openid）首次同步即绑定该微信，若微信已属其他账号则拒绝；
    · 头像不存外站 URL（avatar_url 白名单仅同源/COS）：拉取微信头像二进制走上传链路落库。
    """
    allowed = await redis_rate_limit(
        redis_client, f"rate:syncprofile:{user.id}:{get_client_ip(request)}", 5, 60)
    if not allowed:
        return error(ErrorCode.RATE_LIMIT, "操作过于频繁，请稍后再试")
    # H1 修复（同步微信资料 CSRF）：state 必须由 profile-authorize-url 签发
    # （payload == syncprofile 标记，区别于登录 state），且其 nonce 与当前浏览器 Cookie
    # 匹配——fail-closed，任一环节缺失即拒。封堵「攻击者的 code 被绑到受害者账号」。
    if not req.state:
        return error(ErrorCode.PARAM_ERROR, "微信授权已失效，请重新发起同步")
    if verify_state(req.state) != _SYNC_STATE_MARKER:
        logger.warning(f"同步微信资料 state 校验失败，已拦截: {(req.state or '')[:40]}")
        return error(ErrorCode.PARAM_ERROR, "微信授权校验失败，请重新发起同步")
    st_key = _state_key(req.state)
    try:
        stored = await redis_client.get(st_key)
    except Exception:
        stored = None
    if isinstance(stored, bytes):
        stored = stored.decode()
    cookie_nonce = request.cookies.get(_SYNC_NONCE_COOKIE)
    if not stored or not cookie_nonce or not hmac.compare_digest(cookie_nonce, stored):
        logger.warning("同步微信资料 state 浏览器绑定校验失败，已拦截（nonce 不匹配/过期）")
        return error(ErrorCode.PARAM_ERROR, "微信授权已失效，请重新发起同步")
    session = await code2session(req.code.strip())
    if not session:
        return error(ErrorCode.PARAM_ERROR, "微信授权已失效，请重新发起同步")
    if "snsapi_userinfo" not in (session.get("scope") or ""):
        return error(ErrorCode.PARAM_ERROR, "授权类型不符，请经「同步微信头像昵称」入口重试")
    openid = session["openid"]
    if user.oa_openid and user.oa_openid != openid:
        return error(ErrorCode.NO_PERMISSION, "该微信与当前登录账号不一致")
    info = await fetch_userinfo(session.get("access_token") or "", openid)
    if not info:
        return error(ErrorCode.PARAM_ERROR, "获取微信资料失败，请稍后重试")
    if not user.oa_openid:
        occupied = (await db.execute(select(User).where(
            User.oa_openid == openid))).scalar_one_or_none()
        if occupied and occupied.id != user.id:
            return error(ErrorCode.NO_PERMISSION, "该微信已绑定其他账号")
        # 双向定位：先过台账归属校验（标识已属其他 user_id 则拒绝）再写 users 列——
        # get_db 在返回后统一 commit，若先改写后校验，error 返回也会把半截绑定提交掉。
        if not await identity_svc.link_identity(db, user.id, identity_svc.ID_OA_OPENID, openid):
            return error(ErrorCode.NO_PERMISSION, "该微信已绑定其他账号")
        user.oa_openid = openid
        wx_unionid = session.get("unionid")
        if wx_unionid and not user.unionid:
            # unionid 已属他人时只跳过绑定不报错：昵称头像同步本身仍合法
            if await identity_svc.link_identity(db, user.id, identity_svc.ID_UNIONID, wx_unionid):
                user.unionid = wx_unionid
    else:
        # 已绑定场景：刷新台账活跃时间，保持两个维度可双向回溯
        await identity_svc.record_login_identity(db, user.id, identity_svc.ID_OA_OPENID, openid)
    nick = (info.get("nickname") or "").strip()
    if nick:
        # M3③（第五十七/五十八条）：微信昵称同步后对他人可见，落库前过敏感词。与 user.py 改名
        # 不同——昵称来自微信、且本流程还含头像/openid 绑定，命中敏感词时只跳过昵称落库（保留
        # 原值）+ 告警，不阻断整个同步；否则用户可「在微信改违规昵称→同步」绕过改名入口的检测。
        sw = await compliance_svc.check_sensitive(db, nick[:50])
        if sw["blocked"] or sw["warned"]:
            logger.warning(f"微信昵称命中敏感词已跳过落库 uid={user.id} "
                           f"hits={[h['word'] for h in sw['hits']]}")
        else:
            user.nickname = nick[:50]
    headimg = (info.get("headimgurl") or "").strip()
    if headimg.startswith(("http://", "https://")):
        avatar_url = await _save_remote_avatar(headimg)
        if avatar_url:
            user.avatar_url = avatar_url
    await db.flush()
    # H1：同步成功即消费 state（一次性）并清除绑定 Cookie，防同一授权链接被重放
    try:
        await redis_client.delete(st_key)
    except Exception:
        pass
    resp = JSONResponse(content=success(
        {"nickname": user.nickname, "avatar_url": user.avatar_url}, msg="已同步微信头像昵称"))
    resp.delete_cookie(_SYNC_NONCE_COOKIE, path="/api/auth")
    return resp


async def _save_remote_avatar(url: str) -> Optional[str]:
    """拉取微信头像二进制并走上传链路落库（返回同源/COS 地址）。

    安全边界（SSRF 加固）：
     · 仅允许 http/https，不跟随重定向（防重定向绕过域名/IP 校验）；
     · 【安全审计修复 P2-2】解析一次、校验全部解析结果后，把连接钉死在校验过的 IP 上：
       旧实现校验用 socket.getaddrinfo、请求却由 httpx 另行二次解析，恶意域名可用短 TTL
       在两次解析间切换（DNS rebinding/TOCTOU）先给安全 IP、真请求时指向内网；
       现在 https 仍按原域名做 SNI 与证书主机名校验（连接按 IP、验证按域名，不降低 TLS 强度），
       Host 头也保持原域名；直连 IP 一律拒绝（盲 SSRF 纵深防御）。
    与 /upload/avatar 同口径校验：魔数白名单 + 像素上限 + 体积上限；
    任一环节失败返回 None（调用方保留原头像，不因头像失败回滚昵称）。"""
    import asyncio
    import http.client
    import socket
    import ipaddress
    import ssl
    from urllib.parse import urlparse
    from app.core.api.upload import _is_real_image, MAX_AVATAR_SIZE
    from app.core.utils.oss import oss_service, probe_image_size, MAX_UPLOAD_PIXELS

    parsed = urlparse(url or "")
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None
    host = parsed.hostname
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
    except Exception:
        return None
    # 解析一次：全部解析结果先过私有/回环/链路本地/保留/ multicast 判定，
    # 再把后续连接钉死在首个合法 IP 上（校验与请求共用同一次解析，无 TOCTOU 窗口）
    try:
        infos = socket.getaddrinfo(host, port)
    except Exception:
        return None
    pinned = None
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except Exception:
            return None
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return None
        if pinned is None:
            pinned = info[4][0]
    if pinned is None:
        return None
    host_header = host if port in (80, 443) else f"{host}:{port}"

    def _fetch_blocking() -> bytes:
        # 同步阻塞拉取（在线程池里跑），连接目标固定为校验过的 pinned IP
        if parsed.scheme == "https":
            ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)

            class _PinnedHTTPS(http.client.HTTPSConnection):
                # 基类会用 self.host(=IP) 做 SNI/主机名校验；改写为连 IP、验原域
                def connect(self):
                    sock = socket.create_connection((self.host, self.port), self.timeout)
                    self.sock = self._context.wrap_socket(sock, server_hostname=host)

            conn = _PinnedHTTPS(pinned, port, timeout=15, context=ctx)
        else:
            conn = http.client.HTTPConnection(pinned, port, timeout=15)
        try:
            # 显式 Host：HTTPConnection 检测到调用方已给 host 头即不再自动补 IP 形态的 Host
            conn.request("GET", path, headers={"User-Agent": "Mozilla/5.0", "Host": host_header})
            resp = conn.getresponse()
            if resp.status != 200:
                raise ValueError(f"HTTP {resp.status}")
            # 只读到上限+1 字节，超限即判定失败，不先拉完再拒（防超大响应耗内存）
            return resp.read(MAX_AVATAR_SIZE + 1)
        finally:
            conn.close()

    try:
        content = await asyncio.to_thread(_fetch_blocking)
    except Exception as e:
        logger.warning(f"拉取微信头像失败: {e}")
        return None
    if not content or len(content) > MAX_AVATAR_SIZE:
        return None
    if not _is_real_image(content):
        return None
    size = probe_image_size(content)
    if not size or size[0] <= 0 or size[1] <= 0 or size[0] * size[1] > MAX_UPLOAD_PIXELS:
        return None
    try:
        return await oss_service.upload_avatar(content, "wx_avatar.jpg")
    except Exception as e:
        logger.warning(f"微信头像落库失败: {e}")
        return None


@router.post("/email/register")
async def email_register(req: EmailRegisterRequest, request: Request,
                         db: AsyncSession = Depends(get_db)):
    """Web 站邮箱注册。

    安全边界：
      · 同 IP 注册限流复用 _REGISTER_LIMIT，防止批量注册；
      · 密码走 pbkdf2_sha256 加盐派生，不存明文；
      · 唯一索引 uk_users_email 兜底，IntegrityError 转成友好提示而非 500。
    """
    email = (req.email or "").strip().lower()
    if not _EMAIL_RE.match(email):
        return error(ErrorCode.PARAM_ERROR, "邮箱格式不正确")
    if len(req.password or "") < 8:
        return error(ErrorCode.PARAM_ERROR, "密码长度不能少于 8 位")
    if not await redis_rate_limit(redis_client, f"reg_limit:{get_client_ip(request)}",
                                  _REGISTER_LIMIT, _REGISTER_WINDOW):
        return error(ErrorCode.RATE_LIMIT, "操作过于频繁，请稍后再试")

    # 邮箱验证码校验：若此前已为该邮箱下发过验证码，则必须提供且匹配；
    # 未下发过（无邮件服务/用户未点获取）则跳过，保证当前无邮件环境仍可注册。
    try:
        stored_code = await redis_client.get(f"regcode:{email}")
    except Exception:
        stored_code = None
    if stored_code:
        if not req.code or str(req.code).strip() != str(stored_code):
            return error(ErrorCode.PARAM_ERROR, "验证码无效或已过期，请重新获取")
        try:
            await redis_client.delete(f"regcode:{email}")
        except Exception:
            pass

    # 【安全审计修复】账号枚举：原实现回「该邮箱已注册，请直接登录」，直接把
    # 「某邮箱是否在本站注册过」变成一次请求即可确认的信息（撞库字典先筛一遍、
    # 骚扰/钓鱼定向）。与同文件的 /password/reset-request 同口径：命中已存在账号
    # 只在日志留痕，对外给中性文案。
    # 注意：注册成功必然要下发 token，「成功/失败」本身仍可区分，彻底消除枚举需要
    # 邮箱验证码（未接入邮件服务前做不到）——本修复消除的是「明确告知已注册」这层。
    # 用 scalars().first() 而非 scalar_one_or_none()：uk_users_email 是后加的
    # （sql/migrations/0001），未跑迁移的存量库上同一个邮箱可能存在多行，
    # 命中多行会抛 MultipleResultsFound，把「注册/登录」直接变成 500。
    exists = (await db.execute(
        select(User.id).where(User.email == email).order_by(User.id).limit(1))).scalars().first()
    if exists:
        logger.info("邮箱注册命中已存在账号 ip=%s", get_client_ip(request))
        return error(ErrorCode.PARAM_ERROR, "该邮箱无法完成注册，请更换邮箱或直接登录")

    user = User(email=email, password_hash=_hash_password(req.password),
                last_login_type="email", last_login_value=email)
    try:
        async with db.begin_nested():
            db.add(user)
        await db.flush()
    except IntegrityError:
        logger.info("邮箱注册并发撞唯一索引 ip=%s", get_client_ip(request))
        return error(ErrorCode.PARAM_ERROR, "该邮箱无法完成注册，请更换邮箱或直接登录")

    token = await _issue_token(db, user, req.invite_code)
    resp = JSONResponse(content=success(
        {"user_id": user.id, "is_new": True, "auth_type": "email"}))
    set_auth_cookie(resp, token, request)
    logger.info(f"邮箱注册成功 user_id={user.id}")
    return resp


@router.post("/email/login")
async def email_login(req: EmailLoginRequest, request: Request,
                      db: AsyncSession = Depends(get_db)):
    """Web 站邮箱登录。

    安全边界：
      · 命中已有账号也必须限流，否则可离线穷举密码；
      · 账号不存在与密码错误返回同一提示，避免账号枚举；
      · 恒定时间比较密码摘要。
    """
    email = (req.email or "").strip().lower()
    if not await redis_rate_limit(redis_client, f"login_limit:{get_client_ip(request)}",
                                  _LOGIN_LIMIT, _LOGIN_WINDOW):
        return error(ErrorCode.RATE_LIMIT, "操作过于频繁，请稍后再试")

    # 同上：存量库可能无 uk_users_email，取最早一行避免 MultipleResultsFound
    user = (await db.execute(
        select(User).where(User.email == email, User.status == 1)
        .order_by(User.id).limit(1))).scalars().first()
    if not user or not _verify_password(req.password, user.password_hash):
        return error(ErrorCode.PARAM_ERROR, "邮箱或密码错误")

    user.last_login_type = "email"
    user.last_login_value = email
    token = await _issue_token(db, user, None)
    resp = JSONResponse(content=success(
        {"user_id": user.id, "is_new": False, "auth_type": "email"}))
    set_auth_cookie(resp, token, request)
    return resp


@router.post("/password/reset-request")
async def password_reset_request(req: PasswordResetRequest, request: Request,
                                 db: AsyncSession = Depends(get_db)):
    """密码重置申请。

    当前未接入邮件服务，因此不走「发重置链接」——邮箱未经验证就发链接等于
    给任何人提供了重置他人密码的入口。这里转为人工工单：记录审计日志，
    由客服核验身份后处理。邮箱是否存在都返回相同结果，避免账号枚举。
    """
    email = (req.email or "").strip().lower()
    if not _EMAIL_RE.match(email):
        return error(ErrorCode.PARAM_ERROR, "邮箱格式不正确")
    if not await redis_rate_limit(redis_client, f"reset_limit:{get_client_ip(request)}",
                                  5, _REGISTER_WINDOW):
        return error(ErrorCode.RATE_LIMIT, "操作过于频繁，请稍后再试")

    user = (await db.execute(
        select(User.id).where(User.email == email).order_by(User.id).limit(1))).scalars().first()
    logger.info(f"密码重置申请 email_exists={bool(user)} ip={get_client_ip(request)}")
    return success({
        "submitted": True,
        "message": "重置申请已提交。本站暂未接入邮件通道，为加快处理请到「联系我们」页面"
                    "用同一邮箱留言，客服核验身份后人工协助重置。"
    })


@router.post("/email/send-code")
async def email_send_code(req: SendEmailCodeRequest, request: Request,
                          db: AsyncSession = Depends(get_db)):
    """Web 站注册：下发邮箱验证码。

    安全边界：
     · 同 IP 限流，防止被当作邮件炸弹 / 批量枚举；
     · 验证码存 Redis（TTL 10 分钟），由服务端在校验时比对，前端无法伪造；
     · 未接入真实邮件服务时，仅非生产环境回显 dev_code 便于联调；生产环境必须走真实邮件，
       绝不通过接口返回明文验证码（否则验证码形同虚设）。
    """
    email = (req.email or "").strip().lower()
    if not _EMAIL_RE.match(email):
        return error(ErrorCode.PARAM_ERROR, "邮箱格式不正确")
    # 【体验走查修复 P0】邮件通道未接入时绝不能把验证码写进 Redis。
    # register 的口径是「此前已为该邮箱下发过验证码则必须提供且匹配」：一旦落了 regcode: 键，
    # 该邮箱在 10 分钟内怎么提交都只会收到「验证码无效或已过期」，而邮件永远不会到达——
    # 一个本来可用的注册流程被用户自己点一下按钮堵死，且无任何自救入口。
    # 故未接入邮件时在下发前就拒绝，不写键、不消耗限流额度。
    if not (HAS_EMAIL and send_verification_code is not None):
        logger.info("邮箱验证通道未接入，拒绝下发注册验证码 email_exists_checked ip=%s",
                    get_client_ip(request))
        return error(ErrorCode.PARAM_ERROR, "邮箱验证通道暂未开通，请直接完成注册")
    if not await redis_rate_limit(redis_client, f"sendcode_limit:{get_client_ip(request)}", 5, 3600):
        return error(ErrorCode.RATE_LIMIT, "操作过于频繁，请稍后再试")

    code = f"{secrets.randbelow(900000) + 100000:06d}"
    try:
        await redis_client.set(f"regcode:{email}", code, ex=600)
    except Exception:
        logger.exception("注册验证码写 Redis 失败 email=%s", email)
        return error(ErrorCode.SERVER_ERROR, "验证码服务暂不可用，请稍后重试")

    sent = False
    if HAS_EMAIL and send_verification_code is not None:
        try:
            await send_verification_code(email, code)
            sent = True
        except Exception as e:
            logger.warning("注册验证码邮件发送失败（已落库）: %s", e)

    data = {"message": "验证码已发送，请查收邮箱", "expire_seconds": 600}
    # 邮件实际未发出时，仅在非生产环境回显，便于联调；生产环境不回显明文验证码
    if not sent and not settings.is_prod_env:
        data["dev_code"] = code
    return success(data)
