"""控制台凭证（登录密码 / 操作密码）运行时管理。

设计要点（上线前安全口径）：
- 密码绝不存明文：以 PBKDF2-SHA256（加盐、24 万次迭代）哈希存于 system_configs 的保留键，
  认证时做常量时间比较，杜绝时序侧信道与库泄露即明文失陷。
- 运行时可改、重启不丢：哈希在数据库里，容器重建/重启后依然生效；改密即时生效（每次认证实时读库）。
- 回落机制：保留键未设置时回落 .env 初始值（ADMIN_TOKEN / ADMIN_OPERATE_PASSWORD），
  保证首启可用；一旦在控制台改过密码，.env 旧值立即失效（只认库中哈希）。
- 应急恢复：若忘记登录密码，运维删除对应保留键行即回落 .env，无需改代码。
- 保留键对 /configs 读写屏蔽（见 admin_extra），防止借道配置接口读取或覆写密码哈希。
"""
import asyncio
import hashlib
import hmac
import secrets

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.models import SystemConfig

LOGIN_KEY = "admin_login_pwd_hash"
OPERATE_KEY = "admin_operate_pwd_hash"
RESERVED_KEYS = (LOGIN_KEY, OPERATE_KEY)

_PREFIX = "pbkdf2_sha256"
_ITERATIONS = 240_000


def _hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _ITERATIONS)
    return f"{_PREFIX}${_ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_hash(password: str, stored: str) -> bool:
    """常量时间校验明文与存储哈希；格式异常一律判否（fail-closed）。"""
    try:
        prefix, iters, salt_hex, dk_hex = stored.split("$")
        if prefix != _PREFIX:
            return False
        dk = hashlib.pbkdf2_hmac("sha256", (password or "").encode("utf-8"),
                                 bytes.fromhex(salt_hex), int(iters))
        return hmac.compare_digest(dk.hex(), dk_hex)
    except Exception:
        return False


async def _get_hash(db: AsyncSession, key: str):
    row = (await db.execute(
        select(SystemConfig).where(SystemConfig.config_key == key))).scalar_one_or_none()
    if row is None:
        return None
    val = row.config_value
    return val if isinstance(val, str) and val else None


async def _put_hash(db: AsyncSession, key: str, value: str) -> None:
    row = (await db.execute(
        select(SystemConfig).where(SystemConfig.config_key == key))).scalar_one_or_none()
    if row is not None:
        row.config_value = value
    else:
        db.add(SystemConfig(config_key=key, config_value=value))


async def verify_login_password(db: AsyncSession, provided) -> bool:
    stored = await _get_hash(db, LOGIN_KEY)
    if stored:
        return bool(provided) and await asyncio.to_thread(
            verify_hash, provided, stored)
    from app.config import settings  # 局部导入避免循环依赖
    expected = settings.ADMIN_TOKEN or ""
    if not expected or not provided:
        return False
    return hmac.compare_digest(provided.encode("utf-8"), expected.encode("utf-8"))


async def operate_password_configured(db: AsyncSession) -> bool:
    if await _get_hash(db, OPERATE_KEY):
        return True
    from app.config import settings
    return bool(settings.ADMIN_OPERATE_PASSWORD)


async def verify_operate_password(db: AsyncSession, provided) -> bool:
    stored = await _get_hash(db, OPERATE_KEY)
    if stored:
        return bool(provided) and await asyncio.to_thread(
            verify_hash, provided, stored)
    from app.config import settings
    expected = settings.ADMIN_OPERATE_PASSWORD or ""
    if not expected or not provided:
        return False
    return hmac.compare_digest(provided.encode("utf-8"), expected.encode("utf-8"))


async def set_password(db: AsyncSession, target: str, new_password: str) -> None:
    key = LOGIN_KEY if target == "login" else OPERATE_KEY
    value = await asyncio.to_thread(_hash_password, new_password)
    await _put_hash(db, key, value)


async def hash_user_password(new_password: str) -> str:
    """Hash a normal-user password off the event loop.

    User login accepts the iteration count embedded in the stored hash, so the
    credential module's PBKDF2 format is mutually compatible with auth.py.
    """
    return await asyncio.to_thread(_hash_password, new_password)
