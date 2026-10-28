# -*- coding: utf-8 -*-
"""会员周期额度统计与判定。

模型（额度取自 settings.MEMBERSHIP_QUOTA，按档位给周期总池与单工具单日上限）：
  · 周期总额度 = 该档全部会员工具共享的一个总池；
  · 单工具单日上限 = 独立限制，每日 00:00 重置；
  · bonus_quota 赠送额度：优先扣减、周期/到期清零；
  · 一次消费同时占用「周期总池 1 次」与「该工具当日 1 次」，两者都有余量才放行。

事实来源是订单表：会员每消费一次就多一张 pay_channel='member' 的 0 元消费单，
复用出口提前 return、绝不建单，所以「本周期有几张有效会员单」== 「本周期调用了几次」。
生成失败的单（reports.status='failed'）计数时排除——平台侧失败不该占用户额度。

为什么不用 Redis 计数：单机/开发环境常无 Redis，降级放行会让配额形同虚设。
并发：计数落在订单表，「判定」与「建单」不是同一条语句，必须靠临界区串行化——
锁按用户归一（额度是用户级资源，按内容/结果归一则同一用户并发提交 N 份不同结果
即可各拿一把锁、各读到同一个旧计数、各建单成功，额度被整倍穿透，而不是「至多超 1 次」）；
抢到锁后必须换掉 RR 读快照，且先提交再放锁，否则下一个持锁者读不到本次建单。

【接线状态】usage() 是活的（membership.get_member_status 用它算「本周期已用」）；
consume()/charge_member_view() 这套「判定 + 建 0 元消费单 + 加锁」的写路径全库无调用点：
底座不含需要按次扣额的业务端点，接入此类能力的插件必须自己走 charge_member_view，
或在读侧只用 usage() 自行判定。改这里前先确认你的插件真的调到了它。
"""
import json
import logging
from datetime import datetime
from typing import Optional, Tuple

from sqlalchemy import String, and_, case, cast, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.api.common import redis_acquire_lock_fresh, redis_release_lock_committed
from app.config import settings
from app.core.models import Order, Report, User
from app.core.services.membership import get_member_status, quota_conf
from app.core.utils.payment import PaymentService

logger = logging.getLogger(__name__)

def _member_view_skus():
    # 会员消费单 SKU 全集由各插件 manifest 声明、注册表聚合（纳入共享总池与单日计数）
    from app.plugins import registry
    return registry.member_view_skus()


def day_start(now: Optional[datetime] = None) -> datetime:
    """自然日零点（北京时间）。单工具当日上限按「今天」算，零点重置。"""
    n = now or datetime.now()
    return n.replace(hour=0, minute=0, second=0, microsecond=0)


async def usage(db: AsyncSession, user_id: int, sku_view: str,
                period_start: datetime, period_end: datetime,
                exclude_order_id: Optional[int] = None,
                now: Optional[datetime] = None) -> dict:
    """统计本周期总池已用 + 该工具当日已用。
    返回 {"period_used": n, "daily_used": m}。只数有效消费（completed 且报告未失败）。
    """
    now = now or datetime.now()
    d_start = day_start(now)
    conds = [
        Order.user_id == user_id,
        Order.pay_channel == "member",
        Order.status == "completed",
        Order.sku_code.in_(list(_member_view_skus())),
        Order.created_at >= period_start,
        Order.created_at < period_end,
    ]
    if exclude_order_id is not None:
        conds.append(Order.id != exclude_order_id)
    stmt = (
        select(
            func.count(Order.id),
            func.coalesce(func.sum(case(
                (and_(Order.created_at >= d_start, Order.sku_code == sku_view), 1),
                else_=0)), 0),
        )
        .select_from(Order)
        .outerjoin(Report, Report.order_id == Order.id)
        .where(*conds, or_(Report.id.is_(None), Report.status != "failed"))
    )
    row = (await db.execute(stmt)).one()
    period_used = int(row[0] or 0)
    daily_tool_used = int(row[1] or 0)
    return {"period_used": period_used, "daily_used": daily_tool_used}


async def consume(db: AsyncSession, user_id: int, sku_view: str, order_id: int,
                  now: Optional[datetime] = None) -> Tuple[bool, str]:
    """判定本次会员测算是否放行。返回 (是否放行, 拒绝原因)；原因取 "daily"/"period"/""。

    调用时机：新订单已 flush（拿到 order_id）、触发计费接口之前。被拒时由调用方把
    订单置 cancelled（留痕、不计入用量）。非会员/宽限期（is_vip=False）不放行——
    会员消费路径本就不该走到这里，调用方应先判 vip。
    """
    now = now or datetime.now()
    st = await get_member_status(db, user_id, now=now)
    if not st["is_vip"]:
        return False, "not_vip"
    level = st["level"]
    conf = quota_conf(level)
    period_total = conf["period_total"]
    daily_cap = conf["daily_per_tool"]
    bonus = st["bonus_quota"] or 0
    # 周期窗口：与 membership.period_window 同源（status 已给 period_reset_at）
    from app.core.services.membership import get_membership, period_window
    m = await get_membership(db, user_id)
    p_start, p_end = period_window(m, level, now)

    u = await usage(db, user_id, sku_view, p_start, p_end,
                    exclude_order_id=order_id, now=now)
    # 单工具当日上限
    if daily_cap > 0 and u["daily_used"] >= daily_cap:
        logger.info("额度超限(单日单工具) user=%s sku=%s daily=%s/%s",
                    user_id, sku_view, u["daily_used"], daily_cap)
        return False, "daily"
    # 周期总池（含赠送额度：capacity = 基础 + bonus，bonus 优先扣减）
    capacity = period_total + bonus
    if capacity > 0 and u["period_used"] >= capacity:
        logger.info("额度超限(周期总池) user=%s used=%s/%s(bonus=%s)",
                    user_id, u["period_used"], capacity, bonus)
        return False, "period"
    logger.info("额度放行 user=%s sku=%s daily=%s/%s period=%s/%s",
                user_id, sku_view, u["daily_used"], daily_cap, u["period_used"], capacity)
    return True, ""


async def sync_bonus_used(db: AsyncSession, user_id: int,
                          now: Optional[datetime] = None) -> None:
    """把 bonus_used 落库（= min(本周期 period_used, bonus_quota)），供会员卡片展示「赠送额度剩余」。
    赠送次数不计入退款扣费（第四十八条第2款），故需单独记录已用赠送量。

    此前本函数是死代码——旧签名要调用方传 level/period_start/period_end，且末尾用到的
    get_membership 在本模块没有模块级导入（顶部只导了 get_member_status/quota_conf），一被调用即抛
    NameError，全库因此零调用点，user_memberships.bonus_used 恒为 0，用户用完赠送次数仍显示满额。
    现改为自算周期窗口（不再要求调用方传 period），get_membership/period_window 沿用 consume 的
    函数级导入写法（规避与 membership 的循环导入），并在 charge_member_view 的放行出口调用。
    仅影响展示：额度判定始终走 consume 的实时 usage()（period_used 对比 capacity = period_total
    + bonus），从不读 bonus_used，故本函数失败不改变放行/扣减口径。"""
    now = now or datetime.now()
    # 函数级导入：get_membership/period_window 定义在 membership，模块级导入会与之循环依赖
    from app.core.services.membership import get_membership, period_window
    m = await get_membership(db, user_id)
    if not m:
        return
    st = await get_member_status(db, user_id, now=now)
    bonus = st.get("bonus_quota") or 0
    if bonus <= 0:
        if m.bonus_used:
            m.bonus_used = 0
        return
    # 周期窗口与 consume 同源：period_window 依据会员档 level 与 status 的重置点计算
    p_start, p_end = period_window(m, st.get("level"), now)
    u = await usage(db, user_id, "", p_start, p_end, now=now)
    m.bonus_used = min(u["period_used"], bonus)


# ============ 会员「轻工具」消费记账（实时测算 / 双人解读） ============
# 会员消费单 SKU ↔ 对应单次付费 SKU。复用出口必须两者都认：先用单次付费买过该测算/该对出生信息的
# 用户，升级会员后重看不能因为「只认 vip_*_view」而被重复扣一次额度。
def _view_to_single():
    # 会员消费 SKU ↔ 单次付费 SKU 映射由插件 manifest 声明、注册表聚合
    from app.plugins import registry
    return registry.view_sku_to_single()


async def _reuse_member_view(db: AsyncSession, user_id: int, sku_view: str,
                             biz_key: str) -> Optional[int]:
    """同 biz_key 的已完成消费单 id（会员 0 元单或单次付费单）；命中即「重看」，不占额度。"""
    skus = [sku_view]
    single = _view_to_single().get(sku_view)
    if single:
        skus.append(single)
    q = select(Order.id).where(
        Order.user_id == user_id,
        Order.sku_code.in_(skus),
        Order.status == "completed")
    # 方言兼容：MySQL 用 json_contains；SQLite 下 JSON 落库为 TEXT，用 LIKE 等价实现
    # （与插件双人内容复用的口径保持一致）。
    if settings.DB_TYPE == "sqlite":
        # LIKE 是字符串拼接，必须先排除 % 与 _ 两个通配符：当前 biz_key 为 sha256 十六进制，
        # 天然安全；显式校验是为了将来 biz_key 来源变更时不会悄悄退化成通配符注入。
        safe_key = biz_key or ""
        if not (8 <= len(safe_key) <= 128 and all(c in "0123456789abcdef" for c in safe_key)):
            return None
        q = q.where(cast(Order.biz_data, String).like(f'%"biz_key": "{safe_key}"%'))
    else:
        q = q.where(func.json_contains(Order.biz_data, json.dumps({"biz_key": biz_key})))
    return (await db.execute(q.order_by(Order.id.desc()))).scalars().first()


async def charge_member_view(db: AsyncSession, user: User, sku_view: str, biz_key: str,
                             name: str, redis_client,
                             member_name: Optional[str] = None) -> Tuple[Optional[int], str]:
    """实时测算/双人解读这类「轻工具」的会员消费记账。返回 (order_id_or_None, reason)。

    reason 取值：
      ""                放行。order_id 非空=本次新建会员单（占 1 次额度）；
                        order_id 为 None=命中同 biz_key 的已完成单，属重看，不占额度。
      "daily"/"period"  额度用尽，调用方应回 QUOTA_EXCEEDED。
      "busy"            同一用户的另一笔额度判定正在临界区内，调用方应回 RATE_LIMIT。

    为什么必须建 0 元单：额度的事实来源是订单表（见模块 docstring），不建单就无从计数。
    这正是本条路径此前的缺口——会员调 /live/gua、/pair/interpretation 只过权益门禁
    （check_feature 见到 vip 直接放行），既不建单也不判定额度，于是计费接口可被无限调用，
    平台承担全部成本；而同一工具的单次购买入口又因 MEMBER_COVERED_SINGLE_SKUS 对会员屏蔽，
    用户连付费口径都对不上。建单后 vip_*_view 已登记在 MEMBER_VIEW_SKUS，自动并入共享总池
    与单工具单日上限。

    必须在调用计费接口**之前**调用：先建单判定、再调接口，额度用尽的请求才不会照样打出
    一笔第三方费用。接口调用失败时由调用方 cancel_member_view 作废本单、退回额度占用。

    member_name：问测算人姓名，纯展示字段，不入接口、不进 biz_key。
    与下单路径 api/order.py 对齐写入 biz_data（名字统一截断到 30 字符再落库：
    strip + 截断到 30 字），便于客服按单核对会员路径与单次付费路径的口径一致。
    空值不写入键，避免把快照里塞出 {"biz_key":..., "member_name":""} 这种无意义噪音。
    """
    existing = await _reuse_member_view(db, user.id, sku_view, biz_key)
    if existing:
        return existing, ""
    # 额度临界区按用户归一：与插件报告生成端点的 ensure-report 同一把锁、同一范式，
    # 保证同一用户的全部会员消费（跨工具、跨内容）串行判定。
    lock_key = f"lock:member_quota:{user.id}"
    lock_token = await redis_acquire_lock_fresh(db, redis_client, lock_key, 60)
    if not lock_token:
        return None, "busy"
    try:
        # 换过 RR 快照后重查：并发对手可能刚为同一 biz_key 建完单
        existing = await _reuse_member_view(db, user.id, sku_view, biz_key)
        if existing:
            return existing, ""
        # 会员路径的 biz_data 与下单路径 api/order.py 口径一致：除 biz_key 外可选写入
        # member_name（问测算人姓名，纯展示字段），便于客服按单核对。名字归一与下单路径
        # 完全相同（截断 [:30]），空值不写键避免 {"biz_key":..., "member_name":""}。
        biz_data = {"biz_key": biz_key}
        if member_name is not None:
            # 通用名字归一（strip + 截断 30），不耦合任何具体插件
            _mn = (str(member_name) or "").strip()[:30]
            if _mn:
                biz_data["member_name"] = _mn
        order = Order(
            order_no=PaymentService.generate_order_no(), user_id=user.id, product_id=None,
            sku_code=sku_view, product_type="single", product_name=name,
            amount=0, status="completed", pay_channel="member",
            paid_at=datetime.now(), fulfilled_at=datetime.now(),
            biz_data=biz_data, inviter_id=user.inviter_id)
        db.add(order)
        await db.flush()
        ok, reason = await consume(db, user.id, sku_view, order.id)
        if not ok:
            order.status = "cancelled"
            order.fail_reason = ("会员单工具当日次数已用尽" if reason == "daily"
                                 else "会员周期总额度已用尽")
            await db.flush()
            logger.info("会员额度用尽(轻工具)，拒绝调用计费接口 user_id=%s order_id=%s reason=%s",
                        user.id, order.id, reason)
            return None, reason
        # 本单已 completed（上方 status="completed" + flush）且在额度临界区内，惰性回填
        # bonus_used 供会员卡片展示「赠送额度剩余」。失败只告警不影响放行——bonus_used 仅展示用，
        # 额度判定走 consume 的实时 usage()，与此列无关。
        # 用 SAVEPOINT 隔离：回填内含多次读查询，万一失败只回滚到 SAVEPOINT，绝不污染外层事务
        # （否则本张会员消费单会连同回填异常一起 commit 失败而丢失，那是资金数据不一致）。
        try:
            async with db.begin_nested():
                await sync_bonus_used(db, user.id)
        except Exception:
            logger.warning("回填 bonus_used 失败（不影响额度判定与本单落库）user_id=%s order_id=%s",
                           user.id, order.id, exc_info=True)
        return order.id, ""
    finally:
        # 先提交再放锁：本单必须在下一次额度判定之前落库（见 redis_release_lock_committed）
        await redis_release_lock_committed(db, redis_client, lock_key, lock_token)


async def cancel_member_view(db: AsyncSession, order_id: Optional[int]) -> None:
    """作废一张会员消费单：第三方计费接口失败时退回额度占用。带状态守卫，天然幂等。"""
    if not order_id:
        return
    await db.execute(
        update(Order).where(
            Order.id == order_id, Order.pay_channel == "member",
            Order.status == "completed")
        .values(status="cancelled", fail_reason="计费接口调用失败，未占用额度")
        .execution_options(synchronize_session=False))
