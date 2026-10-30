"""
分销月度排行榜与月度结算服务 V1.3
对应规则第二十三~二十九条、第三十四条第5款：
- 排行榜：名次 + 门槛双达标、并列平分、总池封顶、仅前20名、未达标不发/不降档/不替补
- 次月8号结算：按上月最终档位重算全部订单佣金差额一次性补发，并发放排行榜奖励
- 结算后退款：按最终业绩重核，追回多发的阶梯差额与排行榜奖金
金额口径统一「月度推广总金额」（第六条第3款：名下订单当月支付成功实付之和扣退款）。
"""
import logging
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Optional

from sqlalchemy import select, update, case, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.models import Distributor, CommissionLog, MonthlyPerformance, User
from app.config import settings
from app.core.database import row_lock
from app.core.services.distribution import _money, _ladder_uplift, _capped_rate

logger = logging.getLogger(__name__)


def rank_pool_cap() -> Decimal:
    """第二十五条第3款：单月排行榜奖金总池上限 = 无并列时第 1-20 名奖金之和。"""
    cap = Decimal("0.00")
    for lo, hi, reward, _threshold in settings.DIST_RANK_REWARD:
        cap += Decimal(str(reward)) * (int(hi) - int(lo) + 1)
    return cap


def rank_tier(rank: int) -> Optional[tuple]:
    """返回名次对应的 (单人奖金, 最低月度门槛)；不在 1-20 名区间返回 None。"""
    for lo, hi, reward, threshold in settings.DIST_RANK_REWARD:
        if int(lo) <= rank <= int(hi):
            return (Decimal(str(reward)), Decimal(str(threshold)))
    return None


def last_month_key(now: Optional[datetime] = None) -> str:
    """上一个自然月 YYYY-MM（次月8号结算上月）。"""
    now = now or datetime.now()
    first_this = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    last = first_this - timedelta(days=1)
    return last.strftime("%Y-%m")


async def compute_ranking(db: AsyncSession, month: str) -> dict:
    """第二十三~二十七条：计算某月排行榜。返回 {distributor_id: (rank, reward)}。
    - 竞赛排名（并列同名次、下一名次顺延，如 1,1,3）
    - 并列且达门槛者平分该名次奖金（精确到分）；未达门槛不发（不降档不替补）
    - 违规封禁/注销（status != 1）的推广员不参与排名与发奖
    - 总池封顶 = 无并列时 1-20 名奖金之和
    """
    rows = (await db.execute(
        select(MonthlyPerformance, Distributor.status)
        .join(Distributor, Distributor.id == MonthlyPerformance.distributor_id)
        .where(MonthlyPerformance.month == month,
               MonthlyPerformance.total_amount > 0,
               func.coalesce(MonthlyPerformance.disqualified, 0) == 0,
               Distributor.status == 1)
        .order_by(MonthlyPerformance.total_amount.desc(), MonthlyPerformance.id.asc())
    )).all()

    # 按金额分组，竞赛排名：金额下降时 rank = 位置序号（1-based），并列沿用同一 rank
    groups = []  # [rank, amount, [distributor_id,...]]
    rank = 0
    prev = None
    for i, (mp, _status) in enumerate(rows):
        amt = _money(mp.total_amount)
        if prev is None or amt < prev:
            rank = i + 1
            groups.append([rank, amt, []])
        groups[-1][2].append(mp.distributor_id)
        prev = amt

    result = {}
    cap = rank_pool_cap()
    used = Decimal("0.00")
    for grp_rank, amt, members in groups:
        if grp_rank > 20:
            break
        tier = rank_tier(grp_rank)
        if tier is None:
            continue
        reward_full, threshold = tier
        if amt < threshold:
            continue                       # 第二十四条：未达门槛不发，不降档不替补
        n = len(members)
        share = _money(reward_full / n)    # 第二十五条第2款：并列达标者平均分，精确到分
        for dist_id in members:
            if used + share > cap:         # 第二十五条第3款：总池封顶
                share_eff = cap - used
                if share_eff < Decimal("0.00"):
                    share_eff = Decimal("0.00")
            else:
                share_eff = share
            used += share_eff
            result[dist_id] = (grp_rank, share_eff)
    return result


async def _credit_available(db: AsyncSession, dist_id: int, avail_delta: Decimal, total_delta: Decimal) -> None:
    """把净额入账到可提现余额（avail_delta 可正可负），total_delta 计入累计佣金（可负）。
    正数：原子累加。负数（降档/退款追回）：优先扣可提现，不足清零并计入 debt_commission
    （与 distribution._cancel_one 同口径，不产生负余额）。"""
    avail_delta = _money(avail_delta)
    total_delta = _money(total_delta)
    if avail_delta >= Decimal("0.00"):
        await db.execute(
            update(Distributor).where(Distributor.id == dist_id).values(
                available_commission=Distributor.available_commission + avail_delta,
                total_commission=Distributor.total_commission + total_delta,
            ).execution_options(synchronize_session="fetch"))
        return
    owe = -avail_delta
    res = await db.execute(
        update(Distributor).where(
            Distributor.id == dist_id, Distributor.available_commission >= owe).values(
            available_commission=Distributor.available_commission - owe,
            total_commission=Distributor.total_commission + total_delta,
        ).execution_options(synchronize_session="fetch"))
    if (res.rowcount or 0) == 0:
        avail_now = case((Distributor.available_commission > 0,
                          Distributor.available_commission), else_=Decimal("0.00"))
        await db.execute(
            update(Distributor).where(Distributor.id == dist_id).values(
                available_commission=Decimal("0.00"),
                debt_commission=func.coalesce(Distributor.debt_commission, 0) + (owe - avail_now),
                total_commission=Distributor.total_commission + total_delta,
            ).execution_options(synchronize_session="fetch"))


async def _recompute_logs_uplift(db: AsyncSession, dist_id: int, month: str, final_uplift: Decimal) -> Decimal:
    """把该推广员当月「已结算」流水按 final_uplift 重算佣金，返回相对当前 amount 的差额之和（可负）。
    仅处理 status='settled'：pending 由 T+7 结算、cancelled（退款）由冲回各自处理。"""
    logs = (await db.execute(select(CommissionLog).where(
        CommissionLog.distributor_id == dist_id,
        CommissionLog.month == month,
        CommissionLog.status == "settled"))).scalars().all()
    delta = Decimal("0.00")
    for log in logs:
        base = Decimal(str(log.base_rate or 0))
        new_rate = _capped_rate(base, final_uplift)
        new_amount = _money(Decimal(str(log.order_amount)) * new_rate)
        diff = new_amount - Decimal(str(log.amount))
        if diff != Decimal("0.00"):
            await db.execute(update(CommissionLog).where(CommissionLog.id == log.id).values(
                uplift_rate=final_uplift.quantize(Decimal("0.0001")),
                rate=new_rate.quantize(Decimal("0.0001")),
                amount=new_amount))
            delta += diff
    return delta


async def settle_month(db: AsyncSession, month: str) -> dict:
    """第二十九/二十一条第2款：次月8号结算上月——按最终档位重算全部订单佣金差额一次性补发，
    并发放排行榜奖励。幂等：只处理 settled=0 的月度记录。

    并发防重：调度锁在 Redis 故障时可能「降级放行」，多 worker 下本任务可能被同时执行
    两份；这里用 `row_lock`（MySQL SELECT ... FOR UPDATE）把当月月度记录全部锁住，并发结算
    在数据库层串行化；UPDATE 再带 `settled == 0` 的 CAS 条件兜底，只有真正把 0->1 的那一轮
    才允许入账（阶梯差额补发 + 排行榜奖金），避免重复发钱。"""
    perfs = (await db.execute(row_lock(select(MonthlyPerformance).where(
        MonthlyPerformance.month == month, MonthlyPerformance.settled == 0)))).scalars().all()
    # Ranking must be computed from the same locked snapshot as the money
    # movements. Computing it before the lock lets a concurrent refund change
    # the totals between rank calculation and settlement.
    rank_map = await compute_ranking(db, month)
    now = datetime.now()
    count = 0
    sum_ladder = Decimal("0.00")
    sum_rank = Decimal("0.00")
    for mp in perfs:
        total = _money(mp.total_amount)
        # 第六十条：被取消当月资格（中度/重度违规）不计阶梯上浮，已结算流水重算回基础费率
        if int(mp.disqualified or 0) == 1:
            final_uplift = Decimal("0")
        else:
            final_uplift = _ladder_uplift(total)
        ladder_adjust = await _recompute_logs_uplift(db, mp.distributor_id, month, final_uplift)
        rank, reward = rank_map.get(mp.distributor_id, (None, Decimal("0.00")))
        # CAS：settled 0->1 只允许一轮成功；rowcount==0 说明已被并发结算，跳过本行
        cas = await db.execute(update(MonthlyPerformance).where(
            MonthlyPerformance.id == mp.id, MonthlyPerformance.settled == 0).values(
            ladder_uplift=final_uplift.quantize(Decimal("0.0001")),
            ladder_adjust=ladder_adjust, final_rank=rank, rank_reward=reward,
            settled=1, settled_at=now))
        if (cas.rowcount or 0) == 0:
            continue
        if ladder_adjust != Decimal("0.00") or reward > Decimal("0.00"):
            await _credit_available(db, mp.distributor_id, ladder_adjust + reward, ladder_adjust)
        count += 1
        sum_ladder += ladder_adjust
        sum_rank += reward
    await db.flush()
    return {"month": month, "distributors": count,
            "ladder_adjust": float(sum_ladder), "rank_reward": float(sum_rank)}


async def clawback_distributor_month(db: AsyncSession, dist_id: int, month: str) -> Decimal:
    """第三十四条第5款：结算后订单退款导致不再达档位/名次门槛，按最终业绩重核追回多发部分。
    仅重核本推广员（不重新排名他人）；返回本次追回净额（<=0 表示扣回，0 表示无变化）。"""
    mp = (await db.execute(row_lock(select(MonthlyPerformance).where(
        MonthlyPerformance.distributor_id == dist_id,
        MonthlyPerformance.month == month)))).scalar_one_or_none()
    if not mp or mp.settled != 1:
        return Decimal("0.00")             # 未结算月份：退款只减总额，结算时自然按最终档位计
    total = _money(mp.total_amount)
    new_uplift = _ladder_uplift(total)
    delta = await _recompute_logs_uplift(db, dist_id, month, new_uplift)   # 通常 <= 0
    # 排行榜门槛复核：跌破已得名次门槛则追回奖金（并列/顺延不重算他人）
    rank_back = Decimal("0.00")
    if mp.final_rank and Decimal(str(mp.rank_reward or 0)) > Decimal("0.00"):
        tier = rank_tier(int(mp.final_rank))
        if tier is None or total < tier[1]:
            rank_back = Decimal(str(mp.rank_reward))
    net = delta - rank_back
    if net != Decimal("0.00"):
        await _credit_available(db, dist_id, net, delta)
    claw = -net if net < Decimal("0.00") else Decimal("0.00")
    await db.execute(update(MonthlyPerformance).where(MonthlyPerformance.id == mp.id).values(
        ladder_uplift=new_uplift.quantize(Decimal("0.0001")),
        ladder_adjust=Decimal(str(mp.ladder_adjust or 0)) + delta,
        rank_reward=Decimal(str(mp.rank_reward or 0)) - rank_back,
        clawback=Decimal(str(mp.clawback or 0)) + claw))
    await db.flush()
    return net


async def disqualify_month(db: AsyncSession, dist_id: int, month: str) -> Decimal:
    """第六十条中度/重度：取消当月排行榜与阶梯奖励资格。返回本次追回净额(<=0)。
    - 未结算月：仅标记 disqualified=1，次月8号结算时自然不计阶梯/排行；
    - 已结算月：把阶梯上浮清零重算（追回差额）+ 扣回排行奖金。
    已追回的奖励不补发（第六十条末：中度及以上被取消的当月奖励解冻后不补发）。"""
    mp = (await db.execute(row_lock(select(MonthlyPerformance).where(
        MonthlyPerformance.distributor_id == dist_id,
        MonthlyPerformance.month == month)))).scalar_one_or_none()
    if mp is None:
        return Decimal("0.00")
    await db.execute(update(MonthlyPerformance).where(MonthlyPerformance.id == mp.id)
                     .values(disqualified=1))
    if int(mp.settled or 0) != 1:
        await db.flush()
        return Decimal("0.00")           # 未结算：结算时自然不计，无需追回
    ladder_back = await _recompute_logs_uplift(db, dist_id, month, Decimal("0"))   # <=0
    rank_back = Decimal(str(mp.rank_reward or 0))
    net = ladder_back - rank_back
    if net != Decimal("0.00"):
        await _credit_available(db, dist_id, net, ladder_back)
    await db.execute(update(MonthlyPerformance).where(MonthlyPerformance.id == mp.id).values(
        ladder_uplift=Decimal("0.0000"),
        ladder_adjust=Decimal(str(mp.ladder_adjust or 0)) + ladder_back,
        rank_reward=Decimal("0.00"),
        clawback=Decimal(str(mp.clawback or 0)) + (-net if net < Decimal("0.00") else Decimal("0.00"))))
    await db.flush()
    return net


async def get_top_ranking(db: AsyncSession, month: str, limit: int = 20) -> list:
    """第二十六条：实时预估榜（不构成奖励承诺，最终以次月8号结算为准）。
    返回 [{distributor_id, user_id, total_amount, rank, reward, nickname}]，供 API 层脱敏展示。"""
    rank_map = await compute_ranking(db, month)
    rows = (await db.execute(
        select(MonthlyPerformance, Distributor.user_id)
        .join(Distributor, Distributor.id == MonthlyPerformance.distributor_id)
        .where(MonthlyPerformance.month == month,
               MonthlyPerformance.total_amount > 0,
               func.coalesce(MonthlyPerformance.disqualified, 0) == 0,
               Distributor.status == 1)
        .order_by(MonthlyPerformance.total_amount.desc(), MonthlyPerformance.id.asc())
        .limit(limit)
    )).all()
    out = []
    for mp, uid in rows:
        rank, reward = rank_map.get(mp.distributor_id, (None, Decimal("0.00")))
        nick = (await db.execute(select(User.nickname).where(User.id == uid))).scalar_one_or_none()
        out.append({"distributor_id": mp.distributor_id, "user_id": uid,
                    "total_amount": float(mp.total_amount or 0),
                    "rank": rank, "reward": float(reward),
                    "nickname": nick or ""})
    return out


async def get_my_month(db: AsyncSession, dist_id: int, month: str) -> dict:
    """推广中心：本人某月业绩/档位/预估名次与奖励（实时预估，不构成承诺）。"""
    mp = (await db.execute(select(MonthlyPerformance).where(
        MonthlyPerformance.distributor_id == dist_id,
        MonthlyPerformance.month == month))).scalar_one_or_none()
    total = _money(mp.total_amount) if mp else Decimal("0.00")
    uplift = _ladder_uplift(total)
    rank_map = await compute_ranking(db, month)
    rank, reward = rank_map.get(dist_id, (None, Decimal("0.00")))
    return {
        "month": month,
        "total_amount": float(total),
        "ladder_uplift": float(uplift),
        "est_rank": rank,
        "est_reward": float(reward),
        "settled": bool(mp and mp.settled == 1),
        "final_rank": (int(mp.final_rank) if mp and mp.final_rank else None),
        "rank_reward": float(mp.rank_reward or 0) if mp else 0.0,
        "ladder_adjust": float(mp.ladder_adjust or 0) if mp else 0.0,
    }
