"""
分销服务 V1.3（合规一级直推 + 三级等级 + 月度阶梯 + 60%封顶）
- 仅一级关系、0 门槛、真实消费计佣、退款冲回、T+7 结算、审核制提现
- 单笔佣金 = 订单实付 ×（等级基础费率 + 月度阶梯上浮），封顶 60%；次月8号按最终档位重算补差
- 验证付费用户（首付过7天退款期、终身只计一次）为唯一晋升维度
- 已结算佣金退款冲回不产生负余额，不足计入 debt_commission
- 提现支持劳务报酬代扣个税
"""
import secrets
import logging
from datetime import datetime, timedelta, time as dtime
from decimal import Decimal, ROUND_HALF_UP
from typing import Optional
from sqlalchemy import select, func, update, case
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.models import User, Order, Distributor, CommissionLog, Withdrawal, MonthlyPerformance, VerifiedPaidUser, AttributionTouch
from app.core.database import row_lock
from app.core.services.config_helper import get_float, get_int, get_bool, get_config
from app.config import settings
# 敏感字段（提现实名/收款人姓名/收款账号）写入即加密、读取再解密或脱敏。
from app.core.utils.crypto_field import encrypt_field, decrypt_field, mask_name

logger = logging.getLogger(__name__)
_CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"


def _money(v) -> Decimal:
    return Decimal(str(v)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def _month_key(dt: datetime) -> str:
    """归属自然月 YYYY-MM（以支付成功时间为准，第六条第3款）。"""
    return dt.strftime("%Y-%m")


def _midnight(dt: datetime) -> datetime:
    return datetime.combine(dt.date(), dtime.min)


def _settle_due_at(paid_at: datetime, settle_days: int) -> datetime:
    """第二十八条 T+7：支付当日不计，第7日24点届满、第8日0点起可结算（法定节假日不顺延）。
    即 due = 支付日 00:00 + (settle_days + 1) 天。与退款期/验证用户转正同口径。"""
    return _midnight(paid_at) + timedelta(days=settle_days + 1)


def _base_rate(level: int) -> Decimal:
    """第十三条：等级基础佣金比例 0.30/0.40/0.50。"""
    return Decimal(str(settings.DIST_LEVEL_BASE_RATE.get(int(level or 0), 0.30)))


def _ladder_uplift(total: Decimal) -> Decimal:
    """第二十/二十一条：按月度推广总金额返回阶梯上浮；临界点达到即升（>=门槛）。
    DIST_LADDER 已按门槛从高到低排列，命中第一个 total>=门槛 即返回。"""
    for threshold, up in settings.DIST_LADDER:
        if total >= Decimal(str(threshold)):
            return Decimal(str(up))
    return Decimal("0")


def _capped_rate(base: Decimal, uplift: Decimal) -> Decimal:
    """第十四/十五条：单笔费率=基础+阶梯上浮，封顶 60%。"""
    cap = Decimal(str(settings.DIST_COMMISSION_CAP))
    return min(base + uplift, cap)


def _dist_frozen(dist: Distributor, now: Optional[datetime] = None) -> bool:
    """推广员是否处于冻结态（第十一章分级处置）：
    - status != 1（0冻结/注销、2违规封禁）为硬冻结；
    - frozen_until 未到期（中度冻结7天）为限时冻结。
    计佣、绑定、提现、排行发奖均以此为闸门。"""
    if dist is None:
        return True
    if int(dist.status or 0) != 1:
        return True
    now = now or datetime.now()
    if dist.frozen_until and dist.frozen_until > now:
        return True
    return False


async def resolve_level(db: AsyncSession, dist: Distributor) -> int:
    """返回推广员当前生效等级；顺带把已到生效时刻（达标次日0点）的待升等级落地（第十八条第1款）。
    用带条件的原子 UPDATE 抢占，避免并发结算/计佣重复升级。"""
    now = datetime.now()
    if dist.next_level is not None and dist.next_level_at is not None and dist.next_level_at <= now:
        new_level = int(dist.next_level)
        moved = (await db.execute(
            update(Distributor).where(
                Distributor.id == dist.id,
                Distributor.next_level.isnot(None),
                Distributor.next_level_at <= now,
            ).values(level=new_level, next_level=None, next_level_at=None, level_updated_at=now)
            .execution_options(synchronize_session="fetch"))).rowcount
        if moved:
            dist.level = new_level
            dist.next_level = None
            dist.next_level_at = None
    return int(dist.level or 0)


async def bump_monthly_total(db: AsyncSession, distributor_id: int, month: str, delta) -> Decimal:
    """维护「月度推广总金额」（第六条第3款/第二十条：名下订单当月支付成功实付之和扣退款）。
    upsert monthly_performances 行；累加走数据库侧相对量原子 UPDATE 防并发覆盖。
    返回变更后的总额（下限 0）；同时刷新预估阶梯档位（最终档位由次月8号结算核定）。"""
    delta = _money(delta)
    row = (await db.execute(select(MonthlyPerformance).where(
        MonthlyPerformance.distributor_id == distributor_id,
        MonthlyPerformance.month == month))).scalar_one_or_none()
    if row is None:
        init_total = max(delta, Decimal("0.00"))
        # uq_perf_dist_month 唯一约束：同一推广员「当月首单」并发到账时（SQLite 下 row_lock
        # 退化为无锁），两个事务可能都查到 row is None 各自 INSERT，后提交者撞唯一键抛
        # IntegrityError，进而毒化外层「已付款订单履约」事务——会员已发放、订单已置
        # completed 却因计佣插入失败被整体回滚，只能等平台重试或计佣失败重试补偿。
        # 用 SAVEPOINT 包住插入：冲突只在嵌套事务内回滚，随后重查出对手刚建的行，落到下面的
        # 相对量原子 UPDATE 累加路径（与 membership._get_or_create_locked 同一范式）。
        new_row = MonthlyPerformance(
            distributor_id=distributor_id, month=month,
            total_amount=init_total, ladder_uplift=_ladder_uplift(init_total),
            ladder_adjust=Decimal("0.00"), rank_reward=Decimal("0.00"),
            clawback=Decimal("0.00"), settled=0)
        try:
            async with db.begin_nested():
                db.add(new_row)
            return _money(new_row.total_amount)
        except IntegrityError:
            row = (await db.execute(select(MonthlyPerformance).where(
                MonthlyPerformance.distributor_id == distributor_id,
                MonthlyPerformance.month == month))).scalar_one_or_none()
            if row is None:
                raise
    await db.execute(
        update(MonthlyPerformance).where(MonthlyPerformance.id == row.id).values(
            total_amount=MonthlyPerformance.total_amount + delta
        ).execution_options(synchronize_session="fetch"))
    await db.refresh(row)
    total = _money(row.total_amount)
    if total < Decimal("0.00"):
        await db.execute(update(MonthlyPerformance).where(MonthlyPerformance.id == row.id)
                         .values(total_amount=Decimal("0.00")))
        await db.refresh(row)
        total = Decimal("0.00")
    up = _ladder_uplift(total)
    if Decimal(str(row.ladder_uplift or 0)) != up:
        await db.execute(update(MonthlyPerformance).where(MonthlyPerformance.id == row.id)
                         .values(ladder_uplift=up))
        row.ladder_uplift = up
    return total


async def gen_invite_code(db: AsyncSession, length: int = 6) -> str:
    """使用 secrets 密码学安全随机生成邀请码"""
    for _ in range(10):
        code = "".join(secrets.choice(_CODE_ALPHABET) for _ in range(length))
        exists = await db.execute(select(Distributor.id).where(Distributor.invite_code == code))
        if exists.scalar_one_or_none() is None:
            return code
    for _ in range(10):
        code = "".join(secrets.choice(_CODE_ALPHABET) for _ in range(length + 2))
        exists = await db.execute(select(Distributor.id).where(Distributor.invite_code == code))
        if exists.scalar_one_or_none() is None:
            return code
    return ("X" + datetime.now().strftime("%H%M%S") + secrets.token_hex(3))[:12]


async def _dist_by_code(db: AsyncSession, invite_code: Optional[str]) -> Optional[Distributor]:
    if not invite_code:
        return None
    return (await db.execute(select(Distributor).where(
        Distributor.invite_code == invite_code.strip().upper()))).scalar_one_or_none()


async def record_touch(db: AsyncSession, visitor_key: Optional[str], invite_code: Optional[str],
                       ip: Optional[str] = None, ua: Optional[str] = None) -> bool:
    """第三十六条第1款：用户点击专属链接/扫码/海报进入即记一次触达。
    visitor_key 为未注册访客标识（设备指纹/匹名 device_code）；邀请码非法或推广员
    已注销/冻结/断链时不产生有效触达（第五十条断链、第六十条冻结期暂停新增绑定）。

    调用方：api/distribution.py 的 POST /touch（公开接口，未登录访客上报落地页打开）。
    写入 attribution_touch 后，bind_inviter 才能经 resolve_attribution 做 90 天末次触达
    归因，并回填 bound_user_id；否则绑定只能退回「直传邀请码」那一路。"""
    if not visitor_key or not invite_code:
        return False
    dist = await _dist_by_code(db, invite_code)
    if not dist or dist.status != 1 or dist.link_disabled:
        return False
    now = datetime.now()
    if dist.frozen_until and dist.frozen_until > now:
        return False
    db.add(AttributionTouch(visitor_key=str(visitor_key)[:64], invite_code=dist.invite_code,
                            distributor_id=dist.id, ip=(ip or "")[:45] or None,
                            user_agent=(ua or "")[:255] or None, touched_at=now))
    await db.flush()
    return True


async def resolve_attribution(db: AsyncSession, visitor_key: Optional[str],
                              now: Optional[datetime] = None) -> Optional[Distributor]:
    """第三十六条第2款：90 天归因窗口内取「注册前最后一次有效触达」的推广员；超窗失效。"""
    if not visitor_key:
        return None
    now = now or datetime.now()
    cutoff = now - timedelta(days=settings.DIST_ATTRIBUTION_WINDOW_DAYS)
    touch = (await db.execute(
        select(AttributionTouch).where(
            AttributionTouch.visitor_key == str(visitor_key)[:64],
            AttributionTouch.touched_at >= cutoff)
        .order_by(AttributionTouch.touched_at.desc()).limit(1))).scalar_one_or_none()
    if not touch:
        return None
    return (await db.execute(select(Distributor).where(
        Distributor.id == touch.distributor_id))).scalar_one_or_none()


async def bind_inviter(db: AsyncSession, user: User, invite_code: Optional[str],
                       visitor_key: Optional[str] = None, ip: Optional[str] = None,
                       ua: Optional[str] = None) -> bool:
    """注册/首次绑定时建立推广关系（第三十六、三十七条）。
    优先按触达记录归因（90天窗口 + 末次触达）；无触达记录时回退到直传邀请码（注册即视为一次触达）。
    注册后首次绑定永久有效；已绑定/自购/推广员异常/断链/冻结均不绑定。"""
    if user.inviter_id:
        return False                          # 第三十七条：注册后首次绑定永久有效
    vk = visitor_key or getattr(user, "device_code", None)
    now = datetime.now()
    # 1) 优先按触达记录归因（末次有效触达）
    inviter_dist = await resolve_attribution(db, vk, now) if vk else None
    # 2) 回退：直传邀请码（无触达记录时，注册当场视为一次触达）
    if inviter_dist is None:
        inviter_dist = await _dist_by_code(db, invite_code)
    if not inviter_dist or inviter_dist.user_id == user.id or inviter_dist.status != 1:
        return False
    # 断链/冻结期暂停新增绑定（第五十条断链、第六十条冻结期统一规则）
    if inviter_dist.link_disabled or (inviter_dist.frozen_until and inviter_dist.frozen_until > now):
        return False
    # 设备启发式同人识别：双号自推的最强信号是「两个账号同一设备」。
    # device_code 存于浏览器 localStorage，同一浏览器profile 恒定；同人开二号自绑时两者相同。
    # 命中即拒绝建立推广关系（不绑定、不计佣），从源头切断「小号买、大号拿佣金」自雇舞弊。
    # 仅当两侧 device_code 均非空才比对（微信授权主路径可能无 device_code，不误伤）。
    inviter_user = (await db.execute(select(User).where(
        User.id == inviter_dist.user_id))).scalar_one_or_none()
    if (inviter_user and inviter_user.device_code and user.device_code
            and inviter_user.device_code == user.device_code):
        logger.warning(f"同人设备自绑拦截：invitee={user.id} inviter={inviter_dist.user_id} "
                       f"device_code={user.device_code[:8]}… 拒绝建立推广关系")
        return False
    # 上方 user.inviter_id 判断读的是会话内存快照。授权回调与兜底登录回调都可能携带
    # 邀请码，多 worker 同时处理时双方都能读到 None 并各自写回，导致后写覆盖先写、
    # 两个推广员的 invite_count 各 +1：
    # 用户最终只归属其中一人，另一人的邀请数被凭空虚增（晋升进度失真、数据对不上账）。
    # 带 inviter_id IS NULL 条件的原子 UPDATE 只有真正把 NULL 改成推广员 uid 的那一次
    # 才继续累计邀请数，与全文件 CAS 范式保持一致。
    moved = (await db.execute(
        update(User).where(User.id == user.id, User.inviter_id.is_(None)).values(
            inviter_id=inviter_dist.user_id, invited_at=now)
        .execution_options(synchronize_session=False))).rowcount
    if not moved:
        logger.info(f"并发绑定已被抢先完成，该次放弃 user_id={user.id} "
                    f"inviter={inviter_dist.user_id}")
        return False
    user.inviter_id = inviter_dist.user_id
    user.invited_at = now
    # 邀请人数走数据库侧相对量原子自增，防并发覆盖（与计佣/结算/冲回同一思路）
    await db.execute(
        update(Distributor).where(Distributor.id == inviter_dist.id).values(
            invite_count=func.coalesce(Distributor.invite_count, 0) + 1
        ).execution_options(synchronize_session="fetch"))
    # 回填触达记录的 bound_user_id（仅该次归因命中的访客），便于对账与防作弊溯源
    if vk:
        await db.execute(
            update(AttributionTouch).where(
                AttributionTouch.visitor_key == str(vk)[:64],
                AttributionTouch.distributor_id == inviter_dist.id,
                AttributionTouch.bound_user_id.is_(None)).values(bound_user_id=user.id))
    await db.flush()
    return True


async def ensure_distributor(db: AsyncSession, user: User) -> Distributor:
    dist = (await db.execute(select(Distributor).where(Distributor.user_id == user.id))).scalar_one_or_none()
    if dist:
        return dist
    # 多 worker 下前端首屏会并发拉取分销页多个接口。不能使用「直接 INSERT + 捕获
    # uk_user 冲突兜底」：唯一键冲突后的意向锁/间隙锁可能导致死锁，REPEATABLE READ
    # 快照读也看不到对手尚未提交的行。先对 users 行加记录锁可串行化临界区；
    # 该行必然存在，只加记录锁、不引入间隙锁，
    # 同一用户的并发请求在此排队，先到者建档并提交，后者取得锁后重查即命中。
    await db.execute(
        select(User.id).where(User.id == user.id).with_for_update())
    # 必须用当前读：本事务的快照可能早于对手提交就已建立（函数开头那次快路径查询即已取过快照），
    # 普通快照读看不到对手刚插入的行，会误判为「仍无档案」再次 INSERT 并撞唯一键。
    dist = (await db.execute(
        select(Distributor).where(Distributor.user_id == user.id)
        .with_for_update())).scalar_one_or_none()
    if dist:
        return dist
    code = await gen_invite_code(db)
    dist = Distributor(user_id=user.id, invite_code=code, status=1,
                       total_commission=Decimal("0.00"), pending_commission=Decimal("0.00"),
                       available_commission=Decimal("0.00"), withdrawn_commission=Decimal("0.00"),
                       debt_commission=Decimal("0.00"))
    db.add(dist)
    await db.flush()
    return dist


async def on_order_paid(db: AsyncSession, order: Order) -> Optional[CommissionLog]:
    """订单支付成功计佣（V1.3：等级基础费率 + 月度阶梯上浮，封顶60%；一单一笔 uk_order 幂等）。
    第十九条：本人/自购不计佣金、不计验证用户、不计排行；第六十条：冻结期新订单不计佣金业绩。"""
    if not await get_bool(db, "distribution_enabled", settings.DISTRIBUTION_ENABLED):
        return None
    inviter_id = order.inviter_id
    if not inviter_id or inviter_id == order.user_id:
        return None
    order_amt = _money(order.amount)
    if order_amt <= 0:
        return None                      # 0 元单（会员期内 ensure-report）不计佣、不计业绩
    exists = await db.execute(select(CommissionLog).where(CommissionLog.order_id == order.id))
    if exists.scalar_one_or_none():
        return None
    # 锁定推广员行，保证等级读取、月度总额、余额变更的原子性
    dist_res = await db.execute(row_lock(select(Distributor).where(Distributor.user_id == inviter_id)))
    dist = dist_res.scalar_one_or_none()
    if not dist or dist.status != 1:
        return None
    now = datetime.now()
    # 第六十条冻结期统一规则：冻结期新订单不计佣金业绩
    if dist.frozen_until and dist.frozen_until > now:
        return None
    level = await resolve_level(db, dist)          # 第十八条：升级前订单按原等级，含待升等级落地
    base = _base_rate(level)
    paid_at = order.paid_at or now
    month = _month_key(paid_at)
    # 第二十一条第1款：先把本单计入月度推广总金额，再据变更后总额取「结算当时档位」预结算
    month_total = await bump_monthly_total(db, dist.id, month, order_amt)
    uplift = _ladder_uplift(month_total)
    rate = _capped_rate(base, uplift)              # 第十五条封顶60%
    amount = _money(order_amt * rate)
    if amount <= 0:
        return None
    # 必须在 db.add(log) 之前统计首购：autoflush 会先把新 log 刷入库使计数恒 >=1（见原注释）
    before = await db.execute(select(func.count(CommissionLog.id)).where(
        CommissionLog.distributor_id == dist.id, CommissionLog.buyer_id == order.user_id))
    first_order_from_buyer = (before.scalar() or 0) == 0
    log = CommissionLog(distributor_id=dist.id, buyer_id=order.user_id, order_id=order.id,
                        order_no=order.order_no, order_amount=order_amt,
                        rate=rate.quantize(Decimal("0.0001")),
                        base_rate=base.quantize(Decimal("0.0001")),
                        uplift_rate=uplift.quantize(Decimal("0.0001")),
                        level_snapshot=level, month=month,
                        amount=amount, status="pending")
    db.add(log)
    # 余额累加走数据库侧相对量原子 UPDATE，与并发计佣/冲回互不覆盖（重复计佣由 uk_order 挡住）
    values = {
        "pending_commission": Distributor.pending_commission + amount,
        "total_commission": Distributor.total_commission + amount,
    }
    if first_order_from_buyer:
        values["paid_count"] = func.coalesce(Distributor.paid_count, 0) + 1
    await db.execute(
        update(Distributor).where(Distributor.id == dist.id).values(**values)
        .execution_options(synchronize_session="fetch"))
    # 第十七/三十五条：买家首次付费登记为「待验证付费用户」（过7天退款期后转正，终身只计一次）
    await register_first_payment(db, dist, order, paid_at)
    await db.flush()
    return log


async def register_first_payment(db: AsyncSession, dist: Distributor, order: Order, paid_at: datetime) -> None:
    """第十七条：买家首次付费（任意产品任意金额）登记为待验证付费用户。
    buyer 终身只计一次（uk_buyer），复购不重复；过7天退款期未退款由 promote_verified_users 转正。
    自购已在 on_order_paid 拦截（第十九条）。verify_at 与 T+7 同口径（支付当日不计）。"""
    exist = (await db.execute(select(VerifiedPaidUser.id).where(
        VerifiedPaidUser.buyer_id == order.user_id))).scalar_one_or_none()
    if exist:
        return                              # 终身只计一次
    refund_days = settings.DIST_VERIFY_REFUND_DAYS
    verify_at = _midnight(paid_at) + timedelta(days=refund_days + 1)
    # VerifiedPaidUser.buyer_id 唯一（终身只计一次）：同一买家两笔订单并发到账时（SQLite 下
    # row_lock 退化无锁），双方都可能查到 exist=None 各自 INSERT，后提交者撞唯一键毒化外层履约
    # 事务。用 SAVEPOINT 包住：冲突只在嵌套事务内回滚，对手已登记即视为幂等成功。
    # （佣金流水已在本函数调用前由 on_order_paid 的余额原子 UPDATE 触发 autoflush 落库，
    #  故本 SAVEPOINT 内只有 VerifiedPaidUser 一条待插入，不会与流水插入相互牵连。）
    try:
        async with db.begin_nested():
            db.add(VerifiedPaidUser(distributor_id=dist.id, buyer_id=order.user_id,
                                    first_order_id=order.id, first_paid_at=paid_at,
                                    verify_at=verify_at, status=0))
    except IntegrityError:
        logger.info(f"验证付费用户已被并发登记，幂等跳过 buyer_id={order.user_id}")


async def promote_verified_users(db: AsyncSession, batch_size: int = 200) -> int:
    """定时任务：把已过7天退款期且首单未退款的待验证用户转正（status 0->1），
    累加推广员 verified_paid_count 并触发晋升检查。首单已退款则回退为 status=2。返回转正人数。"""
    now = datetime.now()
    promoted = 0
    last_id = 0
    while True:
        rows = (await db.execute(
            select(VerifiedPaidUser).where(
                VerifiedPaidUser.status == 0,
                VerifiedPaidUser.verify_at <= now,
                VerifiedPaidUser.id > last_id)
            .order_by(VerifiedPaidUser.id.asc()).limit(batch_size))).scalars().all()
        if not rows:
            break
        last_id = rows[-1].id
        for v in rows:
            order = (await db.execute(select(Order).where(
                Order.id == v.first_order_id))).scalar_one_or_none()
            if order and order.status in ("refunded", "refund_pending", "cancelled"):
                await db.execute(update(VerifiedPaidUser).where(
                    VerifiedPaidUser.id == v.id, VerifiedPaidUser.status == 0).values(status=2))
                continue
            moved = (await db.execute(update(VerifiedPaidUser).where(
                VerifiedPaidUser.id == v.id, VerifiedPaidUser.status == 0).values(status=1))).rowcount
            if not moved:
                continue
            await db.execute(update(Distributor).where(Distributor.id == v.distributor_id).values(
                verified_paid_count=func.coalesce(Distributor.verified_paid_count, 0) + 1
            ).execution_options(synchronize_session="fetch"))
            promoted += 1
            dist = (await db.execute(select(Distributor).where(
                Distributor.id == v.distributor_id))).scalar_one_or_none()
            if dist:
                await check_promotion(db, dist)
        await db.flush()
        if len(rows) < batch_size:
            break
    return promoted


async def cum_performance(db: AsyncSession, distributor_id: int) -> Decimal:
    """累计推广业绩（销售业绩）= 各自然月「月度推广总金额」之和。

    口径与月度阶梯/排行榜完全一致（名下订单支付成功实付之和扣退款），由 bump_monthly_total
    在计佣与退款冲回两处维护，所以「刷单后再退掉」的金额不会留在晋升门槛里。
    """
    total = (await db.execute(
        select(func.coalesce(func.sum(MonthlyPerformance.total_amount), 0))
        .where(MonthlyPerformance.distributor_id == distributor_id))).scalar() or 0
    return _money(Decimal(str(total)))


async def promotion_progress(db: AsyncSession, dist: Distributor) -> dict:
    """晋升进度与达标判定的【唯一口径】：check_promotion 判定、推广中心展示、后台查看共用。

    判定与展示各算一遍必然走偏：用户看到的进度与系统实际判定不一致时，用户会按错误预期
    去推广，事后争议无从举证，所以两处必须同源。
    业绩为主（performance）、人数为辅（verified_count），两者同时达标才 qualified。
    """
    level = int(dist.level or 0)
    perf = await cum_performance(db, dist.id)
    # 第十八条第4款：降级重升只认 promo_baseline 之后的新增验证用户
    count = max(int(dist.verified_paid_count or 0) - int(dist.promo_baseline or 0), 0)
    target = level + 1 if level < 2 else None
    perf_need = settings.DIST_PROMOTE_PERFORMANCE.get(target) if target is not None else None
    count_need = settings.DIST_PROMOTE_THRESHOLD.get(target) if target is not None else None
    perf_ok = perf_need is not None and perf >= _money(Decimal(str(perf_need)))
    count_ok = count_need is not None and count >= int(count_need)
    return {
        "level": level,
        "level_name": settings.DIST_LEVEL_NAME.get(level, ""),
        "target_level": target,
        "target_name": settings.DIST_LEVEL_NAME.get(target, "") if target is not None else None,
        # 主门槛：累计推广业绩
        "performance": float(perf),
        "performance_need": float(perf_need) if perf_need is not None else None,
        "performance_ok": bool(perf_ok),
        # 辅助条件：验证付费用户数
        "verified_count": count,
        "count_need": int(count_need) if count_need is not None else None,
        "count_ok": bool(count_ok),
        "qualified": bool(perf_ok and count_ok),
        "pending_level": int(dist.next_level) if dist.next_level is not None else None,
        "pending_at": dist.next_level_at.strftime("%Y-%m-%d %H:%M") if dist.next_level_at else None,
    }


async def check_promotion(db: AsyncSession, dist: Distributor) -> None:
    """第十六/十八条：达到晋升条件 -> 设待升等级，次日0点生效。
    等级永久有效不主动降级；降级重升以 promo_baseline 之后的新增计数（第十八条第4款）。

    晋升条件由「验证付费用户数达标」改为「累计推广业绩（主）+ 验证付费用户数（辅）
    双达标」，人数单独达标不再触发晋升。原口径只看人数，正落在《禁止传销条例》第七条
    第(二)项「以发展人员的数量为依据计算和给付报酬」的表述上（等级决定费率）。
    """
    if int(dist.level or 0) >= 2:
        return                              # 已是合伙人，无更高等级
    if dist.next_level is not None:
        return                              # 已有待升等级，等其生效后再评估下一级
    prog = await promotion_progress(db, dist)
    if not prog["qualified"]:
        return
    target = prog["target_level"]
    nxt = _midnight(datetime.now()) + timedelta(days=1)   # 达标次日0点生效
    moved = (await db.execute(update(Distributor).where(
        Distributor.id == dist.id, Distributor.next_level.is_(None)).values(
            next_level=target, next_level_at=nxt).execution_options(synchronize_session="fetch"))).rowcount
    if moved:
        dist.next_level = target
        dist.next_level_at = nxt
        logger.info(f"[晋升] 待升等级已设置（业绩为主+人数为辅双达标）distributor_id={dist.id} "
                    f"target={target} 业绩={prog['performance']}/{prog['performance_need']} "
                    f"验证付费用户={prog['verified_count']}/{prog['count_need']}")


async def recheck_pending_promotion(db: AsyncSession, dist: Distributor) -> bool:
    """退款后重判「待升等级」是否仍达标，不再达标即撤销（返回是否撤销）。

    第三十五条第3款：已获等级不降级，只撤销尚未生效的待升。
    撤销口径必须与晋升口径同源。退款会同时冲减验证付费用户数（_rollback_verified_user）
    与月度业绩（bump_monthly_total 负值）；任一维度不再达标都必须撤销，避免退款后
    仍在次日 0 点升级。
    """
    if dist.next_level is None:
        return False
    prog = await promotion_progress(db, dist)
    if prog["target_level"] != int(dist.next_level):
        return False                        # 口径不匹配（历史脏数据）时不动数据，交人工核对
    if prog["qualified"]:
        return False
    moved = (await db.execute(update(Distributor).where(
        Distributor.id == dist.id, Distributor.next_level == int(dist.next_level)).values(
            next_level=None, next_level_at=None).execution_options(synchronize_session="fetch"))).rowcount
    if moved:
        dist.next_level = None
        dist.next_level_at = None
        logger.info(f"[晋升撤销] 退款后不再达标，撤销待升等级 distributor_id={dist.id} "
                    f"业绩={prog['performance']}/{prog['performance_need']} "
                    f"验证付费用户={prog['verified_count']}/{prog['count_need']}")
    return bool(moved)


async def apply_pending_promotions(db: AsyncSession, batch_size: int = 200) -> int:
    """定时任务：把已到生效时刻（达标次日0点）的待升等级落地，供展示/无新订单时及时生效。"""
    now = datetime.now()
    applied = 0
    last_id = 0
    while True:
        rows = (await db.execute(
            select(Distributor).where(
                Distributor.next_level.isnot(None),
                Distributor.next_level_at <= now,
                Distributor.id > last_id)
            .order_by(Distributor.id.asc()).limit(batch_size))).scalars().all()
        if not rows:
            break
        last_id = rows[-1].id
        for dist in rows:
            await resolve_level(db, dist)
            applied += 1
        await db.flush()
        if len(rows) < batch_size:
            break
    return applied


async def settle_due_commissions(db: AsyncSession, batch_size: int = 100) -> int:
    """分批处理 pending 佣金，避免一次性全表加载。

    按 id 游标单向推进，保证每条记录在一次运行内只被考察一次。若“未到期”记录
    只 continue 而不推进游标，同一批记录会被反复选中，调度任务可能永久挂起并占住会话。"""
    settle_days = await get_int(db, "commission_settle_days", settings.COMMISSION_SETTLE_DAYS)
    now = datetime.now()
    settled = 0
    last_id = 0
    while True:
        logs = (await db.execute(
            select(CommissionLog)
            .where(CommissionLog.status == "pending", CommissionLog.id > last_id)
            .order_by(CommissionLog.id.asc())
            .limit(batch_size)
        )).scalars().all()
        if not logs:
            break
        last_id = logs[-1].id          # 游标前推：无论本批是否结算，下一轮都不会再选到它们
        for log in logs:
            try:
                order = (await db.execute(select(Order).where(Order.id == log.order_id))).scalar_one_or_none()
                if not order:
                    continue
                if order.status in ("refunded", "cancelled", "refund_pending"):
                    await _cancel_one(db, log)      # 退款订单佣金冲回（第三十四条）
                    continue
                if order.status != "completed" or not order.paid_at:
                    continue
                # 第六十条冻结期统一规则：冻结期佣金不结算，延至解冻后（重度清退已在处置时冲回全部未结算）。
                dist_row = await db.get(Distributor, log.distributor_id)
                if _dist_frozen(dist_row):
                    continue
                # 第二十八条 T+7：支付当日不计，第8日0点起转已结算（法定节假日不顺延）
                if now < _settle_due_at(order.paid_at, settle_days):
                    continue
                amt = Decimal(str(log.amount))
                # 先原子抢占流水状态：退款冲回与结算可能同时命中同一条 pending 流水，
                # 谁先把 status 从 pending 改掉谁生效。不抢占就直接搬钱会出现双扣——
                # 结算把钱移进可提现，冲回又按 pending 分支扣一次待结算余额。
                moved = (await db.execute(
                    update(CommissionLog)
                    .where(CommissionLog.id == log.id, CommissionLog.status == "pending")
                    .values(status="settled", settled_at=datetime.now()))).rowcount
                if not moved:
                    continue        # 已被退款冲回抢先改判 cancelled，本条不再结算
                # 余额搬移同样走相对量原子 UPDATE：与并发计佣、并发冲回互不覆盖。
                # 推广员行不存在时影响 0 行，不影响流水状态推进。
                await db.execute(
                    update(Distributor).where(Distributor.id == log.distributor_id).values(
                        pending_commission=Distributor.pending_commission - amt,
                        available_commission=Distributor.available_commission + amt
                    ).execution_options(synchronize_session="fetch"))
                settled += 1
            except Exception as e:
                logger.error(f"佣金结算单条失败 log_id={log.id}: {e}", exc_info=True)
                continue
        await db.flush()
        if len(logs) < batch_size:
            break
    return settled


async def _cancel_one(db: AsyncSession, log: CommissionLog) -> None:
    if log.status == "cancelled":
        return
    # 抢占流水状态：与 settle_due_commissions 互斥。本函数拿到的 log 是调用方早先 SELECT
    # 出来的快照，结算任务可能已把同一条 pending 流水改判 settled；仍按快照里的 pending
    # 口径冲回就会去扣「待结算余额」，而那笔钱已被搬进「可提现」——待结算被扣成负数，
    # 可提现里的退款佣金却原封不动留在推广员账上。
    # 因此依次尝试 pending / settled 两个来源状态，抢到哪个就按哪个口径冲回。
    prev = None
    for st in ("pending", "settled"):
        claimed = (await db.execute(
            update(CommissionLog)
            .where(CommissionLog.id == log.id, CommissionLog.status == st)
            .values(status="cancelled", cancelled_at=datetime.now(),
                    remark="关联订单退款，佣金冲回")
            .execution_options(synchronize_session="fetch"))).rowcount
        if claimed:
            prev = st
            break
    if prev is None:
        return          # 已被其他路径改判 cancelled，无需重复冲回
    dist = await db.get(Distributor, log.distributor_id)
    amt = Decimal(str(log.amount))
    if dist:
        # 冲回使用数据库侧的相对量原子 UPDATE，而不是「读余额→内存计算→写绝对值」。
        # 后者在无行锁的 SQLite 下会让并发退款互相覆盖，佣金账面与流水对不上。
        # 与同文件提现扣款使用同一套 CAS 口径。
        # synchronize_session="fetch"：让 ORM 身份映射里的 dist 同步到最新值，
        # 否则同一会话后续再读 dist 会拿到冲回前的旧余额。
        if prev == "pending":
            await db.execute(
                update(Distributor).where(Distributor.id == dist.id).values(
                    pending_commission=Distributor.pending_commission - amt,
                    total_commission=Distributor.total_commission - amt
                ).execution_options(synchronize_session="fetch"))
        elif prev == "settled":
            # 可提现余额优先冲回，不足部分计入 debt_commission，不出现负余额。
            # debt_commission 只记不还：全库没有任何自动补债逻辑，后续佣金不会先抵扣欠款，
            # 冲不回的差额就是平台净损失，只能靠人工对账追讨（后台推广员列表以「冲回欠款」展示）。
            # 若要改成自动补债，记账口径需先与业务确认（total_commission 是否随还债回升）。
            # 先带 available_commission >= amt 条件尝试全额冲回（条件本身就保证不会写成负数）；
            # affected==0 说明余额不足，再把余额清零、差额计入欠款。
            res = await db.execute(
                update(Distributor)
                .where(Distributor.id == dist.id, Distributor.available_commission >= amt)
                .values(available_commission=Distributor.available_commission - amt,
                        total_commission=Distributor.total_commission - amt
                        ).execution_options(synchronize_session="fetch"))
            if (res.rowcount or 0) == 0:
                # 差额必须由数据库侧算：dist.available_commission 是本事务早先读到的快照，
                # 并发冲回时它可能已被另一笔冲回清零，仍拿它在 Python 里算差额会把欠款算少
                # （冲不回的钱既不在余额里、也没记进欠款，账面凭空少一笔）。
                # case 取「当前余额与 0 的较大者」，MySQL / SQLite 通用，且全程不依赖内存快照。
                avail_now = case((Distributor.available_commission > 0,
                                  Distributor.available_commission), else_=Decimal("0.00"))
                await db.execute(
                    update(Distributor).where(Distributor.id == dist.id).values(
                        available_commission=Decimal("0.00"),
                        debt_commission=func.coalesce(Distributor.debt_commission, 0) + (amt - avail_now),
                        total_commission=Distributor.total_commission - amt
                    ).execution_options(synchronize_session="fetch"))
    # 流水状态、冲回时间与备注已由上面的抢占 UPDATE 落库，此处不再重复赋值：
    # 重复赋一次 cancelled_at 会因时间戳不同而多产生一条无意义的 UPDATE。


async def on_order_refund(db: AsyncSession, order: Order) -> None:
    """第三十四/三十五条：订单退款（全额口径，与 revoke_refunded_order 一致）——
    冲回佣金 + 扣减月度业绩（排行榜同口径） + 已结算月追回多发奖励 + 回退验证付费用户。"""
    log = (await db.execute(select(CommissionLog).where(CommissionLog.order_id == order.id))).scalar_one_or_none()
    dist_id = month = None
    order_amt = None
    if log:
        dist_id, month, order_amt = log.distributor_id, log.month, Decimal(str(log.order_amount))
        await _cancel_one(db, log)
    # 第三十四条第4款：退款订单不计月度推广总金额（排行榜业绩随之扣减）。
    # 仅当存在佣金流水时扣减——on_order_paid 也只在创建流水时才 bump，两者口径一致。
    if dist_id and month and order_amt:
        await bump_monthly_total(db, dist_id, month, -order_amt)
        # 第三十四条第5款：若该月已次月8号结算，按最终业绩重核追回多发的阶梯差额与排行奖金。
        # 惰性导入：distribution_rank 已在模块级导入本模块，反向依赖会构成循环导入。
        from app.core.services.distribution_rank import clawback_distributor_month
        await clawback_distributor_month(db, dist_id, month)
    # 第三十五条：验证付费用户回退（仅当退款单为触发验证的首单）
    await _rollback_verified_user(db, order)
    # 退款同时冲减了「月度业绩」与「验证付费用户数」，两项都落库之后再统一重判待升等级。
    # 顺序不能提前：只看其中一项的中间态判定会漏掉另一项造成的不达标，而晋升是「业绩为主、
    # 人数为辅」双条件，任一维度跌破门槛都必须撤销尚未生效的待升（已生效等级不降级）。
    if dist_id:
        dist = (await db.execute(select(Distributor).where(
            Distributor.id == dist_id))).scalar_one_or_none()
        if dist:
            await recheck_pending_promotion(db, dist)
    await db.flush()


async def _rollback_verified_user(db: AsyncSession, order: Order) -> None:
    """第三十五条：退款单为买家「首次付费订单」时回退验证付费用户。
    - status=0（待验证/退款期内）→ 直接置 2，从未计入（第三十五条第1款）；
    - status=1（已计入）→ verified_paid_count 扣 1（下限0）后置 2（第三十五条第2款）；
      已获等级不降级；待升等级是否撤销由 on_order_refund 在业绩与人数两项都冲减完毕后
      统一调 recheck_pending_promotion 判定（口径与晋升同源，不在本函数里各算一遍）。
    复购单退款不影响验证状态（验证只认首单）。"""
    vpu = (await db.execute(select(VerifiedPaidUser).where(
        VerifiedPaidUser.first_order_id == order.id))).scalar_one_or_none()
    if not vpu or int(vpu.status or 0) == 2:
        return
    if int(vpu.status or 0) == 0:
        await db.execute(update(VerifiedPaidUser).where(
            VerifiedPaidUser.id == vpu.id, VerifiedPaidUser.status == 0).values(status=2))
        return
    # status == 1：已计入，抢占回退并扣减累计数（下限0，不产生负数）
    moved = (await db.execute(update(VerifiedPaidUser).where(
        VerifiedPaidUser.id == vpu.id, VerifiedPaidUser.status == 1).values(status=2))).rowcount
    if not moved:
        return
    await db.execute(update(Distributor).where(
        Distributor.id == vpu.distributor_id, Distributor.verified_paid_count > 0).values(
        verified_paid_count=Distributor.verified_paid_count - 1
    ).execution_options(synchronize_session="fetch"))


def gen_withdraw_no() -> str:
    # 原「TX+秒级时间戳+4位随机」在同一秒内多笔提现有 1/9000 概率撞号，withdraw_no 唯一约束
    # 会让 apply_withdrawal 撞 IntegrityError（余额已 CAS 扣减、随后整事务回滚，用户见到 500）。
    # 与退款单号 gen_refund_no 同一思路，改用密码学随机十六进制把碰撞概率降到可忽略；
    # 长度 TX+14+10=26，仍在 String(32) 内。
    return "TX" + datetime.now().strftime("%Y%m%d%H%M%S") + secrets.token_hex(5)


def calc_withdraw_tax(amount: Decimal) -> Decimal:
    """劳务报酬个税代扣（简化：按配置固定比例，默认 20%）"""
    if not settings.WITHDRAW_TAX_ENABLED:
        return Decimal("0.00")
    return _money(amount * Decimal(str(settings.WITHDRAW_TAX_RATE)))


async def _today_withdraw_count(db, dist_id) -> int:
    """第三十条：本自然日已用提现次数（00:00 重置）。count_refunded=1 的失败单已返还、不计入。"""
    start = _midnight(datetime.now())
    end = start + timedelta(days=1)
    cnt = (await db.execute(select(func.count()).select_from(Withdrawal).where(
        Withdrawal.distributor_id == dist_id,
        Withdrawal.created_at >= start,
        Withdrawal.created_at < end,
        Withdrawal.count_refunded == 0))).scalar() or 0
    return int(cnt)


async def apply_withdrawal(db, user, amount, channel, account_name, account_no):
    """申请提现（审核制 + 行锁 + 个税代扣 + V1.3 每日2次/00:00重置/实名风控）"""
    if channel not in ("alipay", "wechat", "bank"):
        return False, "收款方式不正确", None
    account_name = (account_name or "").strip()
    account_no = (account_no or "").strip()
    if not account_name or not account_no:
        return False, "请填写实名信息与收款账号", None
    try:
        amt = _money(amount)
    except Exception:
        return False, "金额不正确", None
    withdraw_min = _money(await get_float(db, "withdraw_min", settings.WITHDRAW_MIN))
    if amt < withdraw_min:
        return False, f"满 {withdraw_min} 元才可提现", None
    # 先确保推广员存在，再对其加行锁
    dist = await ensure_distributor(db, user)
    dist = (await db.execute(
        row_lock(select(Distributor).where(Distributor.id == dist.id)))).scalar_one_or_none()
    if _dist_frozen(dist):
        return False, "推广资格已被冻结，请联系客服", None
    # 第三十条：每自然日最多 2 次，00:00 重置（失败返还的次数不计入）
    daily_limit = int(await get_int(db, "withdraw_daily_limit", settings.WITHDRAW_DAILY_LIMIT))
    used_today = await _today_withdraw_count(db, dist.id)
    if used_today >= daily_limit:
        return False, f"每日最多提现 {daily_limit} 次，今日次数已用完，请明日再试", None
    # 第三十条：收款实名须与推广员本人一致。首次提现绑定实名；此后不一致触发风控，
    # 按「暂缓打款/补充核验」处理（仍建审核单锁住余额，交人工核验，不自动打款）。
    # 库里存的是密文，比对前必须先解密。不能拿密文直接比——AES-GCM 每次加密都用
    # 随机 nonce，同一个人两次提现的密文必然不同，用密文比会把「实名一致」误判成
    # 「实名不一致」，从此每一笔二次提现都被挂上风控备注、要人工核验才能打款。
    # 解密失败（密钥被换过/密文被篡改）必须 fail-closed：若按空值处理就会走进下面的
    # 「首次绑定」分支，用新收款人覆盖掉原绑定实名，实名风控形同被绕过。
    try:
        bound_name = (decrypt_field(dist.real_name, strict=True, field="real_name") or "").strip()
    except Exception as e:
        logger.critical(f"[提现风控] 绑定实名解密失败，已拒绝该次提现 distributor_id={dist.id}: {e}")
        return False, "提现实名校验失败，请联系客服处理", None
    risk_note = ""
    if not bound_name:
        # 写入密文。update(...).execution_options(synchronize_session="fetch") 会把新值
        # 同步回会话里的 dist 对象，故不再手工赋值——手工赋明文会让明文留在 identity map
        # 里并可能随后续 flush 再写一次库。
        await db.execute(update(Distributor).where(Distributor.id == dist.id)
                         .values(real_name=encrypt_field(account_name))
                         .execution_options(synchronize_session="fetch"))
    elif bound_name != account_name:
        risk_note = "【风控】收款实名与本人认证不一致，需人工补充核验后打款"
        # 日志里绝不写明文姓名。库里加密了却把明文喷进日志等于白做——日志的访问
        # 权限通常比库松、留存更久，还会被采集进第三方日志平台。只记 id 与脱敏姓名。
        logger.warning(f"[提现风控] 实名不一致 distributor_id={dist.id} "
                       f"认证={mask_name(bound_name)} 收款={mask_name(account_name)}")
    available = _money(dist.available_commission)
    if amt <= 0 or amt > available:
        return False, "可提现佣金不足", None
    auditing = (await db.execute(select(Withdrawal).where(
        Withdrawal.distributor_id == dist.id,
        Withdrawal.status == "auditing"))).scalars().first()
    # 必须用 scalars().first()：SQLite 下 row_lock 退化为无锁，两个并发提现可能都已插进
    # auditing；scalar_one_or_none() 命中多行会抛 MultipleResultsFound → 提现接口 500，
    # 而这两条历史记录永远在，用户从此每次都撞上、再也提不了现。
    if auditing:
        return False, "已有一笔提现正在审核，请等待处理完成", None
    tax = calc_withdraw_tax(amt)
    actual = _money(amt - tax)
    # 余额扣减改为带条件的原子 UPDATE（CAS）：SQLite 下 database.row_lock 会退化为无锁，
    # “读余额→内存计算→写绝对值”在并发下会双花（两请求各读到 100、各写回 0，实际提出 200）。
    # 顺序上必须先 CAS 再 db.add(wd)：否则 CAS 失败 return 时，get_db 仍会 commit 掉已 add 的提现单。
    res = await db.execute(
        update(Distributor)
        .where(Distributor.id == dist.id, Distributor.available_commission >= amt)
        .values(available_commission=Distributor.available_commission - amt,
                withdrawn_commission=Distributor.withdrawn_commission + amt)
        .execution_options(synchronize_session="fetch"))
    if (res.rowcount or 0) == 0:
        return False, "可提现佣金不足", None
    # 收款人姓名与账号加密落库。加密失败或未配密钥时 encrypt_field 会降级为明文并
    # 打 critical 告警，不在此抛异常阻断提现——资金链路可用性优先，但告警必须响到运维。
    wd = Withdrawal(withdraw_no=gen_withdraw_no(), distributor_id=dist.id, user_id=user.id,
                    amount=amt, tax_amount=tax, actual_amount=actual, status="auditing",
                    channel=channel, account_name=encrypt_field(account_name),
                    account_no=encrypt_field(account_no), remark=risk_note or None)
    db.add(wd)
    await db.flush()
    tax_tip = f"，代扣个税 {tax} 元" if tax > 0 else ""
    if risk_note:
        return True, f"提现申请已提交，因收款实名需核验，平台将在核实后1-3个工作日内处理{tax_tip}", wd
    return True, f"提现申请已提交，平台将在1-3个工作日内审核打款{tax_tip}", wd


async def audit_withdrawal(db, withdrawal_id, action, auditor, remark=None, refund_count: bool = True):
    """审核时对提现单加行锁，防止两管理员并发操作结果互相覆盖。
    V1.3 第三十条失败返还：驳回时 refund_count=True（非推广员原因，如平台/银行/风控误判）
    返还当次提现次数（count_refunded=1，不占每日2次限额）；refund_count=False（违规冻结导致）不返还。"""
    wd_res = await db.execute(row_lock(select(Withdrawal).where(Withdrawal.id == withdrawal_id)))
    wd = wd_res.scalar_one_or_none()
    if not wd:
        return False, "提现单不存在"
    if wd.status != "auditing":
        return False, "该提现单已处理"
    if action not in ("paid", "rejected"):
        return False, "审核动作不正确"
    dist = (await db.execute(
        row_lock(select(Distributor).where(Distributor.id == wd.distributor_id)))).scalar_one_or_none()
    amt = Decimal(str(wd.amount))
    # 原子抢占审核权：SQLite 下 row_lock 退化为无锁，「读 status→判断 auditing→写终态」
    # 会被两个管理员的并发请求同时穿透，两人都通过校验；驳回分支还会因此把同一笔金额
    # 退回余额两次（凭空多出可提现佣金）。用带状态条件的原子 UPDATE 抢占，affected==0 即已被处理。
    # MySQL 下 row_lock 已把同一提现单串行化，本条 UPDATE 是双保险；SQLite 下它是唯一护栏。
    new_status = "paid" if action == "paid" else "rejected"
    # 审核人没填备注时必须保留申请时写入的备注（尤其实名风控备注）：直接写 None 会在
    # 点下「确认已打款」时销毁「本笔需人工核验实名」的留痕，事后无法证明该笔提现
    # 经过人工核验，也无法在纠纷中说明平台尽到了核验义务。
    values = {"status": new_status, "audited_at": datetime.now(), "auditor": auditor,
              "remark": (remark or wd.remark)}
    if action == "rejected":
        values["fail_reason"] = (remark or "已驳回")[:200]
        values["count_refunded"] = 1 if refund_count else 0
    claimed = (await db.execute(
        update(Withdrawal)
        .where(Withdrawal.id == withdrawal_id, Withdrawal.status == "auditing")
        .values(**values)
    )).rowcount
    if not claimed:
        return False, "该提现单已处理"
    if action == "rejected" and dist:
        # 驳回退还余额前先冲抵 debt_commission。
        # 场景：订单退款发生在提现审核期间时，_cancel_one 的 settled 冲回分支只认
        # available_commission（看不到挂在审核提现单里的钱），于是把差额记成冲回欠款；
        # 此刻驳回若仍把金额全额退回 available，推广员就能对同一笔已被冲回的佣金二次
        # 提现（余额虚增 + 欠款虚挂，平台净损）。账务口径：驳回=平台不打款，本身即以
        # 「放弃支付」清偿了同额欠款——先冲 debt，剩余才回补可提现余额。
        # 全程用数据库侧相对量表达式（与余额扣减/退回同范式），不依赖内存快照。
        debt = func.coalesce(Distributor.debt_commission, 0)
        debt_off = case((debt >= amt, amt), (debt > 0, debt), else_=Decimal("0.00"))
        prev_debt = Decimal(str(dist.debt_commission or 0))
        await db.execute(
            update(Distributor).where(Distributor.id == dist.id).values(
                available_commission=Distributor.available_commission + (amt - debt_off),
                withdrawn_commission=Distributor.withdrawn_commission - amt,
                debt_commission=debt - debt_off,
            ).execution_options(synchronize_session="fetch"))
        if prev_debt > 0:
            logger.warning(f"[提现驳回·债务冲抵] 驳回 {amt} 元已先冲抵冲回欠款 "
                           f"distributor_id={dist.id} 原欠款={prev_debt}")
    elif action == "rejected":
        # 推广员记录缺失时原本静默跳过：提现单被标成已驳回，申请时扣掉的可提现佣金
        # 却永远回不来，withdrawn_commission 也留在账上——用户的钱凭空消失且无任何线索。
        # 必须留下告警，交人工按 withdrawals 表核对补退。
        logger.error(f"[提现驳回告警] 推广员记录不存在，无法退回余额 "
                     f"withdrawal_id={withdrawal_id} distributor_id={wd.distributor_id} amount={amt}")
    elif action == "paid" and dist and Decimal(str(dist.debt_commission or 0)) > 0:
        # 打款前若名下已有冲回欠款（订单退款已把该佣金冲回但钱已挂账/在途），继续打款
        # 等于把已被冲回的钱再付一次。不替管理员做决定（退款与提现的先后由人工核对），
        # 但必须 ERROR 级告警留痕，交人工复核后再决定打款或驳回。
        logger.error(f"[提现打款告警] 推广员存在冲回欠款仍打款 withdrawal_id={withdrawal_id} "
                     f"distributor_id={dist.id} amount={amt} debt={dist.debt_commission}")
    await db.flush()
    return True, "处理完成"


def mask_account(channel: str, account_no: str) -> str:
    """收款账号脱敏（入参必须是【明文】）。
    库里存的是密文，直接把密文传进来会脱敏出一串 enc:v1: 开头的乱码（既不
    可读也不算脱敏）。从库里取出的值请一律改用 utils.crypto_field.mask_account，
    它先解密再调本函数；本函数只当纯计算保留。
    """
    s = account_no or ""
    if len(s) <= 4:
        return "****"
    if channel == "alipay" and "@" in s:
        name, _, domain = s.partition("@")
        return (name[:2] + "***@" + domain) if len(name) > 2 else "***@" + domain
    # WithdrawRequest 把 account_no 放到最短 1 位，5~8 位的短账号用「前2+后4」
    # 会把整串都拼回来（123456 -> 12****3456），脱敏形同虚设。
    if len(s) <= 8:
        return s[0] + "****"
    return s[:2] + "****" + s[-4:]


# 分销规则展示字段的固定顺序与中文标题（前端按本表顺序渲染，缺失键自动跳过）。
DISTRIBUTION_RULE_LABELS = [
    ("mode", "推广模式"), ("level_desc", "等级与费率"), ("promote_desc", "晋升规则"),
    ("commission_desc", "计佣口径"), ("ladder_desc", "月度阶梯"), ("rank_desc", "月度排行榜"),
    ("settle_desc", "结算规则"), ("attribution_desc", "归因规则"), ("withdraw_desc", "提现规则"),
    ("tax_desc", "纳税说明"), ("forbidden", "合规红线"),
]


async def build_distribution_rules(db: Optional[AsyncSession] = None) -> dict:
    """构建《分销规则》完整展示文案（11 项，第一~六十条），版本号见 settings.DISTRIBUTION_RULE_VERSION。

    以 settings 为权威来源逐项插值（保证文案与实际生效的费率/门槛/周期一致）；
    数值类参数优先取 system_configs 运营可调项（结算天数/提现门槛/每日次数）；
    若传入 db 且存在 distribution_rules（dict），按键覆盖（运营自定义文案，与 init.sql seed 一致）。
    """
    base = settings.DIST_LEVEL_BASE_RATE
    name = settings.DIST_LEVEL_NAME
    badge = settings.DIST_LEVEL_BADGE
    cap = settings.DIST_COMMISSION_CAP
    th = settings.DIST_PROMOTE_THRESHOLD
    perf_th = settings.DIST_PROMOTE_PERFORMANCE
    settle_day = settings.DIST_MONTHLY_SETTLE_DAY
    settle_days = settings.COMMISSION_SETTLE_DAYS
    wd_min = settings.WITHDRAW_MIN
    wd_daily = settings.WITHDRAW_DAILY_LIMIT
    if db is not None:
        settle_days = int(await get_int(db, "commission_settle_days", settle_days))
        wd_min = float(await get_float(db, "withdraw_min", wd_min))
        wd_daily = int(await get_int(db, "withdraw_daily_limit", wd_daily))

    # 等级与费率：普通30%(青铜)/高级40%(白银)/合伙人50%(黄金)，单笔上限60%
    level_desc = "三级等级：" + " / ".join(
        f"{name.get(i, '')}{int(round(base.get(i, 0) * 100))}%({badge.get(i, '')})" for i in (0, 1, 2)
    ) + f"，单笔佣金比例上限 {int(round(cap * 100))}%"

    # 月度阶梯：按门槛从低到高拼接区间（<3000 +0% / 3000-9999 +5% / >=10000 +10%）
    ladder = sorted(settings.DIST_LADDER, key=lambda x: x[0])
    parts = []
    for i, (threshold, up) in enumerate(ladder):
        pct = int(round(float(up) * 100))
        if i == 0 and i + 1 < len(ladder):
            parts.append(f"<{int(ladder[i + 1][0])}元 +{pct}%")
        elif i == len(ladder) - 1:
            parts.append(f"≥{int(threshold)}元 +{pct}%")
        else:
            parts.append(f"{int(threshold)}-{int(ladder[i + 1][0]) - 1}元 +{pct}%")
    ladder_desc = ("月度阶梯上浮（按当月推广总金额）：" + "、".join(parts)
                   + f"（临界点达到即升）；次月 {settle_day} 号按上月最终档位重算补差")

    # 月度排行榜：名次+门槛双达标、并列平分、总池封顶
    rank_parts = []
    pool = 0
    for lo, hi, reward, threshold in settings.DIST_RANK_REWARD:
        lo, hi = int(lo), int(hi)
        seg = f"第{lo}名" if lo == hi else f"第{lo}-{hi}名每人"
        rank_parts.append(f"{seg}{int(reward)}元(月推广≥{int(threshold)}元)")
        pool += int(reward) * (hi - lo + 1)
    rank_desc = ("月度排行榜（名次+门槛双达标）：" + "、".join(rank_parts)
                 + f"；未达门槛不发/不降档/不替补，并列达标者平分该名次奖金，总池封顶 {pool} 元，"
                 + f"次月 {settle_day} 号结算")

    tax_desc = (
        f"推广收入属劳务报酬所得，自然人由平台按累计预扣法代扣代缴个税（当前代扣比例 "
        f"{int(round(settings.WITHDRAW_TAX_RATE * 100))}%），税后金额打款；个体户/持牌机构按规定凭票结算"
        if settings.WITHDRAW_TAX_ENABLED else
        "推广收入属劳务报酬所得，按国家税法规定自行申报纳税，平台不代扣；个体户/持牌机构按规定凭票结算"
    )

    rules = {
        "mode": ("一级直推：不设二级及以上层级、不收取任何入门费、不以付费为推广前提、无团队计酬；"
                 "您只从直接邀请用户的真实消费中获得推广服务费，不按发展人数计酬"),
        "level_desc": level_desc,
        # 文案必须与判定同源（都读 settings 的两个门槛），不得写死数字：把门槛调高却忘改
        # 文案，用户看到的晋升条件就与实际不符——这既是虚假宣传，也是变更未公示。
        "promote_desc": (
            f"晋升以销售业绩为主、推广人数为辅，两项需同时达标："
            f"普通→高级需累计推广业绩≥{perf_th.get(1, 0):g} 元且验证付费用户≥{th.get(1, 0)} 人；"
            f"高级→合伙人需累计推广业绩≥{perf_th.get(2, 0):g} 元且验证付费用户≥{th.get(2, 0)} 人。"
            f"累计推广业绩＝名下订单支付成功实付之和扣退款（与月度阶梯、排行榜同口径）；"
            f"验证付费用户＝归因窗口内首次绑定并首次付费、过 {settings.DIST_VERIFY_REFUND_DAYS} 天退款期未退款、终身只计一次。"
            f"达标次日 0 点生效；退款使任一项跌破门槛时，尚未生效的待升等级将被撤销（已生效等级不降级）。"
            f"等级只决定您本人的服务费率，不因邀请人数本身给付任何报酬"),
        "commission_desc": ("单笔佣金 = 订单实付 ×（等级基础费率 + 月度阶梯上浮），精确到分四舍五入；"
                            "会员订单（新购/续费/升级）均按订单实付金额一次性计佣；本人自购不计佣"),
        "ladder_desc": ladder_desc,
        "rank_desc": rank_desc,
        "settle_desc": (f"佣金 T+{settle_days} 结算（支付成功满 {settle_days}×24 小时转可提现）；"
                        f"每月 {settle_day} 号 0-6 点结算上月阶梯差额与排行榜奖励（含退款追回）"),
        "attribution_desc": (f"归因窗口 {settings.DIST_ATTRIBUTION_WINDOW_DAYS} 天，窗口内多人触达以注册前最后一次有效触达为准；"
                             "注册后首次绑定永久有效"),
        "withdraw_desc": (f"可提现余额满 {wd_min:g} 元可申请，每自然日最多 {wd_daily} 次（00:00 重置），"
                          "提现至本人实名账户，1-3 个工作日到账，平台承担手续费；非推广员原因失败返还当次次数"),
        "tax_desc": tax_desc,
        "forbidden": ("严禁虚假宣传、效果承诺、恐吓诱导、封建迷信、绝对化用语、私下交易、诱导裂变、多级返利暗示；"
                      f"违规按警告 / 冻结 {settings.DIST_FREEZE_DAYS} 天 / 永久清退分级处置，退款订单佣金全额冲回"),
    }
    if db is not None:
        override = await get_config(db, "distribution_rules", None)
        if isinstance(override, dict):
            for k, v in override.items():
                if isinstance(v, str) and v.strip():
                    rules[k] = v
    return rules
