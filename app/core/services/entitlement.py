# -*- coding: utf-8 -*-
"""单次 / 按天权益服务（非会员的付费凭证）—— 通用底盘，零业务词。

权益是「一份内容一把钥匙」：按能力码 feature 记账，以 biz_key 标识具体内容
（一份计算 / 一对出生信息 / 一测算 / 一天），换内容即需再次购买。

哪些 SKU 对应哪个 feature、哪些能力是独立计费（会员不覆盖）、时长卡档位分钟数，
全部由插件 manifest 声明、经注册表聚合；本模块只提供通用机制：
  grant / check / consume / revoke / expire / 时长卡叠加与回收。
"""
import logging
from datetime import datetime, timedelta
from typing import Optional
from sqlalchemy import or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import row_lock
from app.core.models import Order, UserEntitlement

logger = logging.getLogger(__name__)

# 时长卡（限时畅用）专用功能点：权益有效期内全功能放行，
# biz_key 恒 NULL、不参与延迟绑定。
TIMEPASS_FEATURE = "timepass"


def _registry():
    # 函数级导入，避免 core <-> plugins 模块级循环
    from app.plugins import registry
    return registry


async def grant_entitlement(
    db: AsyncSession,
    user_id: int,
    feature: str,
    order_id: int,
    sku_code: str,
    biz_key: Optional[str] = None,
    expire_at: Optional[datetime] = None,
) -> UserEntitlement:
    """支付成功后发放单次/按天权益（feature 由调用方按能力码传入）。"""
    # 同一订单同一功能只发一次（幂等兜底，配合 order_id 唯一约束）
    exist = (await db.execute(select(UserEntitlement).where(
        UserEntitlement.order_id == order_id,
        UserEntitlement.feature == feature))).scalars().first()
    if exist:
        return exist
    ent = UserEntitlement(
        user_id=user_id,
        sku_code=sku_code,
        feature=feature,
        status="available",
        order_id=order_id,
        biz_key=str(biz_key) if biz_key is not None else None,
        expire_at=expire_at,
    )
    db.add(ent)
    await db.flush()
    return ent


async def _bind_card_entitlement(db: AsyncSession, user_id: int, feature: str,
                                 biz_key: str) -> bool:
    """把「卡券兑换产生、尚未绑定内容」的单次权益在首次打开时就地绑定。

    卡券天然「先兑换、后选内容」，兑换时无法知道 biz_key；而 check_feature 按
    `biz_key=?` 查询，NULL 永不命中。这里在首次打开时补绑。

    并发安全：UPDATE 带 `biz_key IS NULL` 条件（CAS），同一时刻只有一条绑成功。
    :return: True 表示本次完成绑定，调用方据此重查。
    """
    if not biz_key or len(str(biz_key)) > 64:
        return False

    from app.core.services.card import CARD_PAY_CHANNEL

    now = datetime.now()
    ent_id = (await db.execute(
        select(UserEntitlement.id)
        .join(Order, Order.id == UserEntitlement.order_id)
        .where(
            UserEntitlement.user_id == user_id,
            UserEntitlement.feature == feature,
            UserEntitlement.status == "available",
            UserEntitlement.biz_key.is_(None),
            Order.pay_channel == CARD_PAY_CHANNEL,
            or_(UserEntitlement.expire_at.is_(None),
                UserEntitlement.expire_at > now),
        )
        .order_by(UserEntitlement.id.asc())
        .limit(1)
    )).scalar_one_or_none()
    if ent_id is None:
        return False

    res = await db.execute(
        update(UserEntitlement)
        .where(UserEntitlement.id == ent_id,
               UserEntitlement.biz_key.is_(None),
               UserEntitlement.status == "available")
        .values(biz_key=biz_key)
    )
    if not res.rowcount:
        return False
    logger.info(f"卡券权益延迟绑定 ent={ent_id} user={user_id} "
                f"feature={feature} biz_key={biz_key}")
    return True


async def check_feature(
    db: AsyncSession,
    user_id: int,
    feature: str,
    biz_key: Optional[str] = None,
) -> dict:
    """功能解锁校验：会员放行；否则查有效权益。
    返回 {allowed, vip, source, entitlements:[{id, biz_key, expire_at}]}。

    独立计费能力（independent_coupon，由插件声明）会员与时长卡均不放行，
    vip 恒 False，allowed 只由该能力的单次权益决定。
    """
    registry = _registry()
    standalone = feature in registry.standalone_features()

    # 会员判定（延迟导入，membership 不依赖本模块模块级）
    from app.core.services.membership import is_vip
    vip = await is_vip(db, user_id)
    if vip and not standalone:
        return {"allowed": True, "vip": True, "source": "vip", "entitlements": []}

    # 时长卡（限时畅用）：有效期内全功能放行；独立计费能力不在全功能边界内。
    tp_expire = None
    if not standalone:
        tp_rows = (await db.execute(
            select(UserEntitlement).where(
                UserEntitlement.user_id == user_id,
                UserEntitlement.feature == TIMEPASS_FEATURE,
                UserEntitlement.status == "available",
                UserEntitlement.expire_at > datetime.now(),
            )
        )).scalars().all()
        if tp_rows:
            tp_expire = max(r.expire_at for r in tp_rows)
    if tp_expire:
        return {"allowed": True, "vip": False, "source": "timepass",
                "timepass_expire": tp_expire.strftime("%Y-%m-%d %H:%M"),
                "entitlements": []}

    # 独立计费能力必须带 biz_key（一份内容一把钥匙），否则不放行
    if standalone and biz_key is None:
        return {"allowed": False, "vip": False, "source": "none", "entitlements": []}

    now = datetime.now()
    stmt = select(UserEntitlement).where(
        UserEntitlement.user_id == user_id,
        UserEntitlement.feature == feature,
        UserEntitlement.status == "available",
    )
    if biz_key is not None:
        stmt = stmt.where(UserEntitlement.biz_key == str(biz_key))
    result = await db.execute(stmt.order_by(UserEntitlement.id.desc()))
    items = result.scalars().all()

    if not items and biz_key is not None:
        # 未直接命中：尝试绑定卡券兑换留下的未绑定权益
        if await _bind_card_entitlement(db, user_id, feature, str(biz_key)):
            items = (await db.execute(
                stmt.order_by(UserEntitlement.id.desc()))).scalars().all()

    valid = []
    for it in items:
        if it.expire_at and it.expire_at <= now:
            continue
        valid.append({
            "id": it.id,
            "biz_key": it.biz_key,
            "sku_code": it.sku_code,
            "order_id": it.order_id,
            "expire_at": it.expire_at.strftime("%Y-%m-%d %H:%M") if it.expire_at else None,
        })
    return {
        "allowed": len(valid) > 0,
        "vip": False,
        "source": "entitlement" if valid else "none",
        "entitlements": valid,
    }


async def consume_entitlement(db: AsyncSession, entitlement_id: int) -> None:
    """把单条权益置为 used（CAS：仅 available 时生效，可重复调用）。
    供运维手工核销；当前「一份内容可重复查看」语义下主链路不核销。

    【接线状态】全库无调用点（含管理端）：核销入口尚未接任何接口，改状态请走数据库工单，
    不要以为存在某个「一键核销」的后台按钮。"""
    await db.execute(
        update(UserEntitlement)
        .where(UserEntitlement.id == entitlement_id, UserEntitlement.status == "available")
        .values(status="used", used_at=datetime.now())
    )


async def revoke_by_order(db: AsyncSession, order_id: int) -> int:
    """退款时撤销该订单下尚未使用的权益，已使用的不动，返回撤销条数。"""
    result = await db.execute(
        update(UserEntitlement)
        .where(UserEntitlement.order_id == order_id, UserEntitlement.status == "available")
        .values(status="revoked")
    )
    return result.rowcount or 0


async def max_timepass_expire(db: AsyncSession, user_id: int,
                              now: Optional[datetime] = None,
                              for_update: bool = False) -> datetime:
    """当前畅用权益的最晚到期时刻；无有效权益时返回 now（从此刻起算）。

    新卡 expire_at = 本结果 + 本卡分钟数，保证「重复兑换顺延叠加」语义，
    且每张卡落一条属于自己订单的权益行，退款 / 核销可按订单精确回收。
    """
    now = now or datetime.now()
    stmt = select(UserEntitlement).where(
        UserEntitlement.user_id == user_id,
        UserEntitlement.feature == TIMEPASS_FEATURE,
        UserEntitlement.status == "available",
        UserEntitlement.expire_at > now,
    ).order_by(UserEntitlement.expire_at.desc()).limit(1)
    if for_update:
        stmt = row_lock(stmt)
    row = (await db.execute(stmt)).scalars().first()
    if row and row.expire_at and row.expire_at > now:
        return row.expire_at
    return now


async def revoke_timepass_by_order(db: AsyncSession, order_id: int) -> int:
    """撤销某张时长卡兑换单贡献的畅用时长，并把其后叠加段整体前移，返回受影响行数。

    时长卡顺延叠加，只撤销中间一段，用户仍能靠后续行白享这一段；
    故同时把其后所有有效行前移该档分钟数，做到按订单精确回收。
    """
    row = (await db.execute(
        select(UserEntitlement).where(
            UserEntitlement.order_id == order_id,
            UserEntitlement.feature == TIMEPASS_FEATURE,
            UserEntitlement.status == "available",
        ).order_by(UserEntitlement.expire_at.asc()).limit(1)
    )).scalars().first()
    if not row:
        return 0
    row_expire = row.expire_at
    minutes = _registry().timepass_sku_minutes().get(row.sku_code or "", 0)
    if not minutes or not row_expire:
        row.status = "revoked"
        await db.flush()
        logger.warning(f"时长卡撤销缺分钟映射 sku={row.sku_code} order_id={order_id}")
        return 1
    delta = timedelta(minutes=minutes)
    later = (await db.execute(
        select(UserEntitlement).where(
            UserEntitlement.user_id == row.user_id,
            UserEntitlement.feature == TIMEPASS_FEATURE,
            UserEntitlement.status == "available",
            UserEntitlement.id != row.id,
            UserEntitlement.expire_at > row_expire,
        )
    )).scalars().all()
    for r in later:
        r.expire_at = r.expire_at - delta
    row.status = "revoked"
    await db.flush()
    logger.info(f"时长卡权益撤销 order_id={order_id} minutes={minutes} "
                f"shifted_rows={len(later)}")
    return 1 + len(later)


async def expire_due_entitlements(db: AsyncSession) -> int:
    """定时任务：把过期的按天权益标记 expired。"""
    result = await db.execute(
        update(UserEntitlement)
        .where(
            UserEntitlement.status == "available",
            UserEntitlement.expire_at.isnot(None),
            UserEntitlement.expire_at <= datetime.now(),
        )
        .values(status="expired")
    )
    return result.rowcount or 0
