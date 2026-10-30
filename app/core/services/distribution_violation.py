"""
分销违规分级处置服务 V1.3（第十一章 第六十条）
级别与措施：
- 轻度 minor  ：警告 + 限24h整改；扣该违规订单佣金；记入档案（不冻结、不降级）
- 中度 moderate：冻结7天(frozen_until) + status=0 + 断链 + 降一级(重升基准=当前验证数)
                 + 取消当月排行/阶梯资格 + 扣违规订单佣金
- 重度 severe ：永久取消推广资格(status=2) + 断链 + 扣全部未结算佣金 + 追回已结算违规佣金及违规奖励
- 涉嫌违法 illegal：立即冻结(status=0,无固定期限) + 断链 + 固定证据（移交司法由运营线下执行）
冻结期统一规则（第六十条末）：暂停推广资格、专属链接暂停新增绑定、冻结期新订单不计佣金业绩、
已绑定关系保留、解冻后恢复但中度及以上被取消的当月奖励不补发。
所有处置写入 violation_records 留痕（第五十九条：不少于3年）。
"""
import logging
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Optional

from sqlalchemy import select, update, case
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.models import Distributor, CommissionLog, ViolationRecord
from app.core.database import row_lock
from app.config import settings
from app.core.services.distribution import _money, _cancel_one
from app.core.services.distribution_rank import disqualify_month

logger = logging.getLogger(__name__)

MINOR = "minor"
MODERATE = "moderate"
SEVERE = "severe"
ILLEGAL = "illegal"
MEASURE = "measure"          # 行政措施（断链/解冻），非违规定级


async def _reload_locked(db: AsyncSession, dist_id: int) -> Optional[Distributor]:
    """加行锁重新加载推广员，保证处置读到最新状态（并发处置/计佣互斥）。"""
    return (await db.execute(
        row_lock(select(Distributor).where(Distributor.id == dist_id)))).scalar_one_or_none()


async def _cancel_order_commission(db: AsyncSession, dist_id: int, order_id: int) -> Decimal:
    """扣该违规订单佣金：冲回其佣金流水（复用退款冲回口径，pending 扣待结算/settled 扣可提现）。"""
    log = (await db.execute(select(CommissionLog).where(
        CommissionLog.order_id == order_id,
        CommissionLog.distributor_id == dist_id))).scalar_one_or_none()
    if not log or log.status == "cancelled":
        return Decimal("0.00")
    amt = _money(log.amount)
    await _cancel_one(db, log)
    await db.execute(update(CommissionLog).where(CommissionLog.id == log.id)
                     .values(remark="违规订单，佣金扣除"))
    return amt


async def _forfeit_all_pending(db: AsyncSession, dist_id: int,
                               remark: str = "重度违规，未结算佣金全部扣除") -> Decimal:
    """重度：扣全部未结算佣金——把所有 pending 流水置 cancelled，清零待结算、扣减累计佣金。"""
    logs = (await db.execute(select(CommissionLog).where(
        CommissionLog.distributor_id == dist_id,
        CommissionLog.status == "pending"))).scalars().all()
    total = Decimal("0.00")
    for log in logs:
        amt = _money(log.amount)
        claimed = (await db.execute(update(CommissionLog).where(
            CommissionLog.id == log.id, CommissionLog.status == "pending").values(
            status="cancelled", cancelled_at=datetime.now(), remark=remark))).rowcount
        if claimed:
            total += amt
    if total > Decimal("0.00"):
        # 使用相对量原子扣减，不能把 pending_commission 直接置 0。本处置与并发计佣可能
        # 同时在跑（4 worker），另一事务刚累加的待结算佣金会被这行一并清零，而
        # total_commission 只按本批流水做相对扣减——待结算余额与流水、与累计佣金从此对不
        # 上，破坏「可提现 + 待结算 + 欠款 = 累计 - 已提现」的账目恒等式，事后无法对账。
        # 改为相对量扣减 + case 兜底到 0，与 _cancel_one / _credit_available 同口径。
        new_pending = Distributor.pending_commission - total
        await db.execute(update(Distributor).where(Distributor.id == dist_id).values(
            pending_commission=case((new_pending > 0, new_pending), else_=Decimal("0.00")),
            total_commission=Distributor.total_commission - total
        ).execution_options(synchronize_session="fetch"))
    return total


async def warn_minor(db: AsyncSession, dist: Distributor, reason: str, order_id: Optional[int] = None,
                     evidence=None, handler: str = "system") -> ViolationRecord:
    """第六十条轻度：警告并限24小时删除/整改；扣该违规订单佣金；记入档案。不冻结、不降级。"""
    dist = await _reload_locked(db, dist.id) or dist
    claw = Decimal("0.00")
    if order_id:
        claw = await _cancel_order_commission(db, dist.id, order_id)
    rec = ViolationRecord(distributor_id=dist.id, user_id=dist.user_id, level=MINOR, action="warn",
                          reason=(reason or "")[:500], evidence=evidence, order_id=order_id,
                          clawback_amount=claw, handler=handler, status="applied")
    db.add(rec)
    await db.flush()
    logger.warning(f"[违规·轻度] distributor_id={dist.id} 警告整改 reason={reason} 扣佣={claw}")
    return rec


async def freeze_moderate(db: AsyncSession, dist: Distributor, reason: str, order_id: Optional[int] = None,
                          evidence=None, handler: str = "admin") -> ViolationRecord:
    """第六十条中度：冻结7天 + 断链 + 降一级 + 取消当月排行/阶梯资格 + 须重学重考。"""
    dist = await _reload_locked(db, dist.id) or dist
    now = datetime.now()
    frozen_until = now + timedelta(days=settings.DIST_FREEZE_DAYS)
    level_before = int(dist.level or 0)
    level_after = max(level_before - 1, 0)
    claw = Decimal("0.00")
    if order_id:
        claw += await _cancel_order_commission(db, dist.id, order_id)
    # 取消当月排行榜与阶梯奖励资格（未结算仅标记；已结算追回已发奖励）
    dq = await disqualify_month(db, dist.id, now.strftime("%Y-%m"))
    if dq < Decimal("0.00"):
        claw += -dq
    # 降级：promo_baseline=当前验证付费用户数，重升只认此后新增；撤销待升等级。
    await db.execute(update(Distributor).where(Distributor.id == dist.id).values(
        status=0, frozen_until=frozen_until, link_disabled=1,
        level=level_after, promo_baseline=int(dist.verified_paid_count or 0),
        next_level=None, next_level_at=None, level_updated_at=now
    ).execution_options(synchronize_session="fetch"))
    rec = ViolationRecord(distributor_id=dist.id, user_id=dist.user_id, level=MODERATE, action="freeze",
                          reason=(reason or "")[:500], evidence=evidence, order_id=order_id,
                          frozen_until=frozen_until,
                          level_before=level_before, level_after=level_after, clawback_amount=claw,
                          handler=handler, status="applied")
    db.add(rec)
    await db.flush()
    logger.warning(f"[违规·中度] distributor_id={dist.id} 冻结至{frozen_until:%Y-%m-%d} "
                   f"降级 {level_before}->{level_after} 断链 追回={claw}")
    return rec


async def terminate_severe(db: AsyncSession, dist: Distributor, reason: str, order_id: Optional[int] = None,
                           evidence=None, handler: str = "admin") -> ViolationRecord:
    """第六十条重度：永久取消推广资格 + 扣全部未结算佣金 + 追回已结算违规佣金及违规奖励 + 断链。
    封禁关联账号、移送司法由运营线下执行，本处仅终止推广身份并留痕。"""
    dist = await _reload_locked(db, dist.id) or dist
    now = datetime.now()
    forfeit = await _forfeit_all_pending(db, dist.id)
    claw = Decimal("0.00")
    if order_id:
        claw += await _cancel_order_commission(db, dist.id, order_id)
    dq = await disqualify_month(db, dist.id, now.strftime("%Y-%m"))
    if dq < Decimal("0.00"):
        claw += -dq
    level_now = int(dist.level or 0)
    await db.execute(update(Distributor).where(Distributor.id == dist.id).values(
        status=2, link_disabled=1, frozen_until=None, next_level=None, next_level_at=None,
        level_updated_at=now
    ).execution_options(synchronize_session="fetch"))
    rec = ViolationRecord(distributor_id=dist.id, user_id=dist.user_id, level=SEVERE, action="terminate",
                          reason=(reason or "")[:500], evidence=evidence, order_id=order_id,
                          level_before=level_now, level_after=level_now,
                          clawback_amount=forfeit + claw, handler=handler, status="applied")
    db.add(rec)
    await db.flush()
    logger.error(f"[违规·重度] distributor_id={dist.id} 永久清退 扣未结算={forfeit} 追回={claw}")
    return rec


async def freeze_illegal(db: AsyncSession, dist: Distributor, reason: str, evidence=None,
                         handler: str = "admin") -> ViolationRecord:
    """第六十条涉嫌违法：立即冻结（无固定期限）+ 断链 + 固定证据。冻结期佣金不结算；
    待司法结论后由运营 force 恢复或转重度清退。"""
    dist = await _reload_locked(db, dist.id) or dist
    await db.execute(update(Distributor).where(Distributor.id == dist.id).values(
        status=0, frozen_until=None, link_disabled=1,
        next_level=None, next_level_at=None
    ).execution_options(synchronize_session="fetch"))
    rec = ViolationRecord(distributor_id=dist.id, user_id=dist.user_id, level=ILLEGAL, action="freeze",
                          reason=(reason or "")[:500], evidence=evidence,
                          handler=handler, status="applied")
    db.add(rec)
    await db.flush()
    logger.error(f"[违规·涉嫌违法] distributor_id={dist.id} 立即冻结、固定证据、移交司法")
    return rec


async def disable_link(db: AsyncSession, dist: Distributor, reason: str, handler: str = "admin",
                       reenable: bool = False) -> ViolationRecord:
    """第五十八条第4款紧急措施/断链：停用或恢复专属链接（暂停/恢复新增归因绑定，已绑定关系保留）。"""
    dist = await _reload_locked(db, dist.id) or dist
    await db.execute(update(Distributor).where(Distributor.id == dist.id).values(
        link_disabled=0 if reenable else 1).execution_options(synchronize_session="fetch"))
    rec = ViolationRecord(distributor_id=dist.id, user_id=dist.user_id, level=MEASURE,
                          action="link_on" if reenable else "link_off",
                          reason=(reason or "")[:500], handler=handler, status="applied")
    db.add(rec)
    await db.flush()
    return rec


async def unfreeze(db: AsyncSession, dist: Distributor, handler: str = "admin", force: bool = False):
    """中度冻结解冻：冻结期满后恢复 status=1、解除断链。
    被取消的当月奖励不补发（第六十条末）。force=True 为运营强制恢复（涉嫌违法核实无误/申诉成功）。"""
    dist = await _reload_locked(db, dist.id) or dist
    now = datetime.now()
    if int(dist.status or 0) == 2 and not force:
        return False, "重度违规已永久清退，不可解冻（如申诉成功请走强制恢复）"
    if not force:
        if int(dist.status or 0) == 1 and not (dist.frozen_until and dist.frozen_until > now):
            return False, "推广员当前未处于冻结状态"
        if dist.frozen_until is None:
            return False, "涉嫌违法/无限期冻结，需运营核实司法结论后强制恢复"
        if dist.frozen_until > now:
            return False, f"冻结期未满（{settings.DIST_FREEZE_DAYS}天），暂不可解冻"
    await db.execute(update(Distributor).where(Distributor.id == dist.id).values(
        status=1, link_disabled=0, frozen_until=None).execution_options(synchronize_session="fetch"))
    rec = ViolationRecord(distributor_id=dist.id, user_id=dist.user_id, level=MEASURE,
                          action="restore" if force else "unfreeze",
                          reason="强制恢复推广资格" if force else "冻结期满，解冻恢复推广资格",
                          handler=handler, status="applied")
    db.add(rec)
    await db.flush()
    return True, "已解冻，推广资格恢复"


async def get_violation_history(db: AsyncSession, dist_id: int, limit: int = 50) -> list:
    """处置档案（第五十九条留痕）：按时间倒序返回违规处置记录，供后台/推广中心展示。"""
    rows = (await db.execute(select(ViolationRecord).where(
        ViolationRecord.distributor_id == dist_id)
        .order_by(ViolationRecord.id.desc()).limit(limit))).scalars().all()
    return [{
        "id": r.id, "level": r.level, "action": r.action, "reason": r.reason,
        "clawback_amount": float(r.clawback_amount or 0),
        "level_before": r.level_before, "level_after": r.level_after,
        "frozen_until": r.frozen_until.strftime("%Y-%m-%d %H:%M") if r.frozen_until else None,
        "handler": r.handler, "status": r.status,
        "created_at": r.created_at.strftime("%Y-%m-%d %H:%M") if r.created_at else None,
    } for r in rows]
