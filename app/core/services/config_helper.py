"""系统配置读取辅助：system_configs 表中的运营可调参数"""
import json
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.models import SystemConfig


async def get_config(db: AsyncSession, key: str, default=None):
    """读取单个系统配置，JSON 自动反序列化"""
    result = await db.execute(select(SystemConfig).where(SystemConfig.config_key == key))
    cfg = result.scalar_one_or_none()
    if not cfg:
        return default
    val = cfg.config_value
    if isinstance(val, str):
        try:
            val = json.loads(val)
        except (json.JSONDecodeError, TypeError):
            pass
    return val


async def get_float(db: AsyncSession, key: str, default: float) -> float:
    val = await get_config(db, key, default)
    try:
        return float(val)
    except (TypeError, ValueError):
        return default


async def get_int(db: AsyncSession, key: str, default: int) -> int:
    val = await get_config(db, key, default)
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


async def get_bool(db: AsyncSession, key: str, default: bool) -> bool:
    val = await get_config(db, key, default)
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.strip().lower() in ("1", "true", "yes", "on")
    return bool(val)
