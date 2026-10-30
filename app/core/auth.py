"""认证与授权模块：JWT、Redis Token 黑名单、FastAPI 用户依赖、Cookie 会话"""
import logging
import secrets
from datetime import datetime, timezone, timedelta
from typing import Tuple

import jwt
import redis.asyncio as redis
from fastapi import Depends, HTTPException, Request, Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.config import settings
from app.core.database import get_db
from app.core.models import User

logger = logging.getLogger(__name__)

# Cookie 名称（httpOnly Cookie 存 token，兼容旧版 localStorage）
AUTH_COOKIE_NAME = "auth_token"

# CSRF：跨域部署（SameSite=none）下 Cookie 会随跨站请求自动携带，
# 此时必须由前端 fetch 统一附加一个自定义头作为「同源意图」证明。
# 跨站攻击者用 <form> 提交无法设置自定义头；用 fetch 设置则会触发 CORS 预检，
# 而 CORS_ORIGINS 生产不放行 *，预检必被拒——两条路都走不通，CSRF 即被阻断。
# 同源部署（SameSite=lax，默认）浏览器本就不向跨站 POST 携带 lax Cookie，无需该校验。
CSRF_HEADER_NAME = "X-Requested-With"
_UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# FastAPI Bearer 安全方案
security = HTTPBearer(auto_error=False)

# Redis 异步客户端（全局单例；本地开发 SQLite 模式无 Redis 也能跑——所有操作 try-except 降级）
try:
    redis_client = redis.from_url(
        settings.redis_url,
        decode_responses=True,
        # 连接与读写超时上限：Redis 不可达时快速失败，避免限流/黑名单调用阻塞到
        # 操作系统 TCP 超时把请求拖成假死（详见 config.REDIS_SOCKET_TIMEOUT 注释）。
        socket_connect_timeout=settings.REDIS_SOCKET_TIMEOUT,
        socket_timeout=settings.REDIS_SOCKET_TIMEOUT,
    )
except Exception as _e:
    logger.warning(f"Redis 连接初始化失败，部分功能将降级: {_e}")
    redis_client = None


def create_jwt_token(user_id: int, expire_days: int = None,
                     auth_version: int = 0) -> Tuple[str, str]:
    """创建 JWT token，返回 (token, jti)。jti 用于黑名单定位。"""
    expire_days = expire_days or settings.JWT_EXPIRE_DAYS
    now = datetime.now(timezone.utc)
    jti = secrets.token_hex(16)
    payload = {
        "sub": str(user_id),
        "exp": now + timedelta(days=expire_days),
        "iat": now,
        "jti": jti,
        "type": "access",
        "aud": settings.JWT_AUDIENCE,
        "iss": settings.JWT_ISSUER,
        "ver": int(auth_version or 0),
    }
    token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return token, jti


def decode_jwt_token(token: str) -> dict:
    """解码并校验 JWT（aud/iss/exp/signature），返回 payload。
    失效/伪造/跨服务混淆一律抛 HTTPException(401)，对外统一文案：
    区分「token 已过期/无效/跨服务」会泄露太多状态，统一返回「未登录或登录已失效」，
    客户端拿到的 detail 不可枚举，原文仅入日志便于排查。"""
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            audience=settings.JWT_AUDIENCE,
            issuer=settings.JWT_ISSUER,
        )
        return payload
    except jwt.ExpiredSignatureError:
        logger.info("JWT 校验失败：已过期")
        raise HTTPException(status_code=401, detail="未登录或登录已失效")
    except jwt.InvalidTokenError as e:
        # 写明细分原因到日志（含 aud/iss 不匹配等），对外只回统一文案
        logger.info(f"JWT 校验失败：{type(e).__name__}: {e}")
        raise HTTPException(status_code=401, detail="未登录或登录已失效")


async def _is_token_blacklisted(jti: str) -> bool:
    """检查 token 是否已被拉黑（Redis 黑名单）。
    Redis 故障时的降级策略由 REDIS_FAIL_CLOSED 控制（与限流器同口径）：
    False 放行保可用；True 拒绝保安全——注销/禁用场景下被拉黑的 token
    不应在故障窗口内继续可用。"""
    if not jti or redis_client is None:
        return False
    try:
        return bool(await redis_client.exists(f"bl:{jti}"))
    except Exception as e:
        if settings.REDIS_FAIL_CLOSED:
            logger.error(f"检查 token 黑名单失败，REDIS_FAIL_CLOSED=true 拒绝放行 jti={jti[:8]}: {e}")
            return True
        logger.warning(f"检查 token 黑名单失败，降级放行 jti={jti[:8]}: {e}")
        return False


async def add_to_blacklist(user_id: int, jti: str, ttl_seconds: int) -> bool:
    """把当前 token 加入黑名单（退出登录时调用）。TTL 对齐 token 剩余有效期。

    返回 True 表示「已撤销 / 无需撤销」，False 表示「撤销失败，该 token 在自然
    过期前仍然有效」。

    调用方必须能区分「已拉黑」与「Redis 故障、什么都没做」，并在后者如实告知
    用户会话尚未失效；否则共享设备上的 token 仍可使用到自然过期，事故复盘时
    也无法回答「谁在何时退出失败」。
    Redis 未配置（redis_client=None，sqlite 轻量/开发模式）不属于故障，
    按项目既有约定返回 True（与 _is_token_blacklisted 同口径），仅 warning 留痕。
    """
    if not jti:
        return False
    if redis_client is None:
        logger.warning("Redis 未配置，token 未进入黑名单（开发/轻量模式）uid=%s", user_id)
        return True
    try:
        await redis_client.set(f"bl:{jti}", str(user_id), ex=max(1, ttl_seconds))
        return True
    except Exception as e:
        logger.error(f"写入 token 黑名单失败，token 在自然过期前仍有效 jti={jti[:8]}: {e}")
        return False


async def add_user_to_blacklist(user_id: int, ttl_seconds: int = None) -> None:
    """把整个用户加入黑名单（注销/禁用时调用）。默认永久（ttl=None）。"""
    if redis_client is None:
        return
    try:
        key = f"ubl:{user_id}"
        if ttl_seconds:
            await redis_client.set(key, "1", ex=ttl_seconds)
        else:
            await redis_client.set(key, "1")
    except Exception as e:
        logger.warning(f"写入用户黑名单失败 uid={user_id}: {e}")


# ============ 设备码「已释放」标记============
# 设备码是外部浏览器下的长期登录凭证（无口令、无过期、登出不影响），落在共享或
# 二手设备上会直接暴露账号。解绑时必须同时登记「该码已失效」，登录链路据此明确拒绝；
# 若只把 users.device_code 置空，旧码会进入「查无用户 → 新建账号」分支并静默建号。
_DEVICE_RELEASED_PREFIX = "dev_released:"
# 保留期：设备码只存在于浏览器 localStorage，90 天足以覆盖旧设备/二手设备的复用窗口
_DEVICE_RELEASED_TTL = 90 * 24 * 3600


async def mark_device_code_released(device_code: str) -> bool:
    """登记设备码为「已释放」。返回 True 表示登记成功（调用方才可安全解绑）。

    Redis 故障或未配置时返回 False：此时**不允许解绑**——解绑后旧码仍可登录，
    却已无法在登录链路拦住它，结果是静默建空号，比不解绑更糟（fail-closed）。
    """
    code = (device_code or "").strip()
    if not code:
        return False
    if redis_client is None:
        logger.warning("Redis 未配置，拒绝释放设备码（无法保证旧码失效）")
        return False
    try:
        await redis_client.set(_DEVICE_RELEASED_PREFIX + code, "1", ex=_DEVICE_RELEASED_TTL)
        return True
    except Exception as e:
        logger.error("登记设备码释放标记失败，按 fail-closed 不解绑: %s", e)
        return False


async def is_device_code_released(device_code: str) -> bool:
    """设备码是否已被释放（登录链路据此拒绝并给出明确文案）。

    本函数刻意 fail-open：它只承担「拒绝 + 明确提示」，Redis 故障时放行的最坏
    结果是回到异常状态的静默建号行为，不构成越权或资损；反过来若 fail-closed，
    Redis 一宕机全部设备码用户都登录不了，是不可接受的可用性事故。
    """
    code = (device_code or "").strip()
    if not code or redis_client is None:
        return False
    try:
        return bool(await redis_client.exists(_DEVICE_RELEASED_PREFIX + code))
    except Exception as e:
        logger.warning("检查设备码释放标记失败，按未释放放行: %s", e)
        return False


async def _is_user_blacklisted(user_id: int) -> bool:
    """检查用户是否整体被拉黑。降级策略与 _is_token_blacklisted 同口径。"""
    if redis_client is None:
        return False
    try:
        return bool(await redis_client.exists(f"ubl:{user_id}"))
    except Exception as e:
        if settings.REDIS_FAIL_CLOSED:
            logger.error(f"检查用户黑名单失败，REDIS_FAIL_CLOSED=true 拒绝放行 uid={user_id}: {e}")
            return True
        logger.warning(f"检查用户黑名单失败 uid={user_id}: {e}")
        return False


def set_auth_cookie(response: Response, token: str, request: Request) -> None:
    """在响应上设置 httpOnly Auth Cookie。"""
    # SameSite：跨域部署（前端域名 ≠ API 域名）时用 none + Secure
    samesite = settings.AUTH_COOKIE_SAMESITE or "lax"
    # 生产环境全站 HTTPS，Cookie 恒置 Secure；跨域(SameSite=none)时同样需要
    secure = samesite.lower() == "none" or settings.is_prod_env
    response.set_cookie(
        key=AUTH_COOKIE_NAME,
        value=token,
        httponly=True,
        samesite=samesite,
        secure=secure,
        max_age=settings.JWT_EXPIRE_DAYS * 24 * 3600,
        path="/",
    )


def clear_auth_cookie(response: Response) -> None:
    """清除 httpOnly Auth Cookie"""
    response.delete_cookie(
        key=AUTH_COOKIE_NAME,
        path="/",
    )


async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> User:
    """FastAPI 依赖：从 Authorization Bearer 头或 httpOnly Cookie 解析当前用户。

    优先 Bearer 头（兼容旧前端 localStorage 存量），其次 Cookie（新会话）。

    必须复用请求级 get_db 会话（FastAPI 对同一依赖在单请求内缓存，故与路由中的
    db: Depends(get_db) 是同一个 session）。返回的 User 必须处于 persistent 状态，
    使路由/服务层对 status、昵称头像、邀请绑定等属性的修改随请求事务一起提交。
    """
    token = None
    token_from_cookie = False
    if credentials is not None:
        token = credentials.credentials
    if not token:
        token = request.cookies.get(AUTH_COOKIE_NAME)
        token_from_cookie = bool(token)
    if not token:
        raise HTTPException(status_code=401, detail="未登录或登录已失效")

    # CSRF：Cookie 会话 + 不安全方法 + 跨域部署（SameSite=none）三者同时成立时，
    # 要求请求携带自定义头证明同源意图；缺失即视为跨站伪造，拒绝。
    if (token_from_cookie
            and request.method.upper() in _UNSAFE_METHODS
            and (settings.AUTH_COOKIE_SAMESITE or "lax").lower() == "none"
            and not request.headers.get(CSRF_HEADER_NAME)):
        logger.warning(f"CSRF 防护拦截：Cookie 会话的 {request.method} 缺少 {CSRF_HEADER_NAME} 头")
        raise HTTPException(status_code=403, detail="未登录或登录已失效")

    payload = decode_jwt_token(token)
    user_id_str = payload.get("sub")
    if not user_id_str:
        raise HTTPException(status_code=401, detail="未登录或登录已失效")
    try:
        user_id = int(user_id_str)
    except (ValueError, TypeError):
        raise HTTPException(status_code=401, detail="未登录或登录已失效")

    # 检查 token 黑名单（登出后的旧 token）
    jti = payload.get("jti")
    if await _is_token_blacklisted(jti):
        raise HTTPException(status_code=401, detail="未登录或登录已失效")

    # 复用请求级会话查询用户：返回的实例处于 persistent 状态，
    # 路由/服务层对其属性的修改会随 get_db 的 commit 一并提交
    user = (await db.execute(
        select(User).where(User.id == user_id, User.status == 1))).scalar_one_or_none()
    if not user:
        logger.info(f"get_current_user 拒绝：uid={user_id} 在 DB 不存在或 status≠1")
        raise HTTPException(status_code=401, detail="未登录或登录已失效")
    try:
        token_version = int(payload.get("ver", 0))
    except (TypeError, ValueError):
        token_version = -1
    if token_version != int(user.auth_version or 0):
        logger.info("get_current_user 拒绝：uid=%s 会话版本已失效", user_id)
        raise HTTPException(status_code=401, detail="未登录或登录已失效")
    if await _is_user_blacklisted(user_id):
        logger.info(f"get_current_user 拒绝：uid={user_id} 已被拉黑")
        raise HTTPException(status_code=403, detail="未登录或登录已失效")
    return user
