"""双向定位：内部 user_id ↔ 登录标识 的双向唯一映射台账（services/identity）。

用户唯一性必须由两个维度共同钉死——
  ① 程序自生成的 ID（users.id）；
  ② 登录时数据（设备码 / 服务号 openid / 小程序 openid / unionid）。
只认其一都会出错单：只认 user_id，同一人微信/设备两个账号会把订单与开票劈成两半；
只认登录标识，注销归档（标识加后缀释放唯一约束）后历史订单就对不上人。

本模块提供三件事：
  · record_login_identity：每次登录/绑定写台账（upsert，刷新 last_login_at）；
  · find_user_id_by_identity：标识 → user_id（反向定位，含 users 表已归档但台账仍存的历史）；
  · link_identity：把新标识挂到既有 user_id 上；若该标识已属他人则拒绝返回 False
    （uk_identity_value 兜底，调用方据此决定「合并」还是「新建账号」）。

users 表四列（device_code/oa_openid/mp_openid/unionid）仍是登录热路径直查源；
本台账是审计与兜底校验源，两者由登录链路同步维护，不允许只写一边。
"""
import logging
from datetime import datetime
from typing import Optional

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.models import UserIdentity

logger = logging.getLogger(__name__)

# 标识类型常量：与 users 表四列一一对应，禁止调用方手写字符串
ID_DEVICE = "device"
ID_OA_OPENID = "oa_openid"
ID_MP_OPENID = "mp_openid"
ID_UNIONID = "unionid"
_VALID_TYPES = (ID_DEVICE, ID_OA_OPENID, ID_MP_OPENID, ID_UNIONID)


async def record_login_identity(db: AsyncSession, user_id: int, id_type: str,
                                id_value: Optional[str]) -> None:
    """登录/绑定成功后写台账：已存在则刷新 last_login_at，不存在则插入。

    失败只告警不抛出：台账是审计兜底，不能因为它把登录主流程打挂；
    但静默丢失等于没记，必须留 ERROR 供告警通道叫人来看。
    插入走 SAVEPOINT（begin_nested）：并发首登撞 uk_identity_value 时只回滚台账
    这一条，不能整会话 rollback——那会把登录主流程未提交的绑定/订单修改一并丢掉。"""
    if not id_value or id_type not in _VALID_TYPES:
        return
    value = str(id_value)[:64]
    try:
        row = (await db.execute(select(UserIdentity).where(
            UserIdentity.id_type == id_type,
            UserIdentity.id_value == value))).scalar_one_or_none()
        if row is None:
            db.add(UserIdentity(user_id=user_id, id_type=id_type, id_value=value))
            try:
                async with db.begin_nested():
                    await db.flush()
            except IntegrityError:
                # 并发首登同时 INSERT 同一标识：uk_identity_value 拦下后者，属预期竞态，
                # SAVEPOINT 已回滚，外层事务与登录主流程不受影响。
                logger.warning(f"[身份台账] 并发写入撞唯一约束，已回滚到保存点 "
                               f"id_type={id_type} uid={user_id}")
        else:
            if row.user_id != user_id:
                # 台账与登录链路出现分裂：同一标识指向两个 user_id。
                # 登录热路径以 users 表唯一列为准，这里只留痕不改写，交由人工核对。
                logger.error(f"[身份台账] 标识归属冲突 id_type={id_type} "
                             f"ledger_uid={row.user_id} login_uid={user_id}，需人工核对")
                return
            row.last_login_at = datetime.now()
            await db.flush()
    except Exception as e:
        logger.error(f"[身份台账] 写入失败 id_type={id_type} uid={user_id}: {e}",
                     exc_info=True)


async def find_user_id_by_identity(db: AsyncSession, id_type: str,
                                   id_value: Optional[str]) -> Optional[int]:
    """标识 → user_id 反向定位。返回 None 表示台账无此标识。"""
    if not id_value or id_type not in _VALID_TYPES:
        return None
    row = (await db.execute(select(UserIdentity.user_id).where(
        UserIdentity.id_type == id_type,
        UserIdentity.id_value == str(id_value)[:64]))).scalar_one_or_none()
    return row


async def identities_of_user(db: AsyncSession, user_id: int) -> list:
    """user_id → 全部登录标识（含历史），客服/财务双向核对用。"""
    rows = (await db.execute(select(UserIdentity).where(
        UserIdentity.user_id == user_id).order_by(UserIdentity.id))).scalars().all()
    return [{"id_type": r.id_type, "id_value": r.id_value,
             "first_seen_at": r.first_seen_at.strftime("%Y-%m-%d %H:%M") if r.first_seen_at else None,
             "last_login_at": r.last_login_at.strftime("%Y-%m-%d %H:%M") if r.last_login_at else None}
            for r in rows]


async def link_identity(db: AsyncSession, user_id: int, id_type: str,
                        id_value: Optional[str]) -> bool:
    """把标识挂到既有 user_id（账号合并/补绑场景）。

    返回 False 表示该标识已归属其他 user_id——调用方必须放弃合并并保持账号分离，
    绝不能改台账归属：历史订单/佣金/开票都挂在原 user_id 上，改归属等于把别人的
    财务记录划到另一个人名下。"""
    if not id_value or id_type not in _VALID_TYPES:
        return False
    existing = await find_user_id_by_identity(db, id_type, id_value)
    if existing is not None and existing != user_id:
        logger.warning(f"[身份台账] 拒绝改挂：id_type={id_type} 已属 uid={existing}，"
                       f"请求挂到 uid={user_id}")
        return False
    await record_login_identity(db, user_id, id_type, id_value)
    return True
