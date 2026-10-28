"""
定时任务调度 v7
1. 清理过期缓存（每日凌晨）
2. 关闭超时订单（每5分钟）
3. 失败报告自动退款（每10分钟，三态处理 + 报告状态同步 T17）
4. 退款失败重试（每30分钟，超3次告警 T6）
5. 佣金 T+N 结算（每30分钟，分批 M8）
6. 过期按天权益清理（每小时）
7. 过期月会员 level 同步（每小时，M7）
8. 计佣失败重试（每15分钟，T5）
9. 验证付费用户转正+等级生效（每30分钟，V1.3 第十六~十八条）
10. 月度阶梯差额补发+排行榜奖励结算（次月8号 01:00，V1.3 第二十九条）
11. 支付主动查单/掉单补偿（每2分钟，A2）
12. 每日渠道对账轧账（默认 10:30，A3）
13. AI 生成日志留存期清理（每日 03:30，A4）
14. 退款主动核实（每5分钟，A2 退款侧）
M20：分布式锁 TTL 统一延长到 600 秒，避免长任务超时重复执行
"""
import logging
from datetime import datetime, timedelta
from sqlalchemy import select, update, delete
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from app.core.database import AsyncSessionLocal
from app.core.models import ResultCache, Order, Report, Refund, CommissionFailLog, AiGenerationLog
from app.core.utils.payment import apply_refund, gen_refund_no, has_real_payment, no_payment_reason, query_refund
from app.core.services.distribution import settle_due_commissions, on_order_paid, promote_verified_users, apply_pending_promotions
from app.core.services.distribution_rank import settle_month, last_month_key
from app.core.services.entitlement import expire_due_entitlements
from app.core.services.membership import expire_overdue_memberships

from app.core.services.fulfillment import revoke_refunded_order
from app.core.services.refund_state import apply_channel_refund_status
from app.core.services.payment_sync import sync_stuck_orders
from app.core.services.reconcile import reconcile_recent
from app.config import settings

# 卡券兑换单的支付渠道标识（与 services.card.CARD_PAY_CHANNEL 一致）。
# 刻意写成字面量而非 import：卡券模块可以单独回滚删除，若此处 import 它，
# 一旦模块缺失整个 app 都起不来 —— 一个可选业务模块不能把整站带崩。
CARD_CHANNEL = "card"

logger = logging.getLogger(__name__)
scheduler = AsyncIOScheduler()
_LOCK_TTL = 600  # M20：统一 10 分钟


async def _acquire_lock(lock_name: str, ttl_seconds: int = _LOCK_TTL) -> bool:
    """调度任务互斥锁。

    V-2：Redis 故障时 fail-closed（拒绝放行）。原实现降级返回 True（视为抢到锁），
    多 worker 部署下自动退款/退款重试/月度结算等关键任务会被同时执行两份——各向支付平台
    发起一笔真实退款、重复发放佣金与排行榜奖金。Redis 故障时本轮直接跳过，任务在下一轮
    （interval/cron 周期）自然补跑；对财务类任务来说「暂时不跑」远好于「并发重复跑」。"""
    try:
        from app.core.auth import redis_client
        ok = await redis_client.set(f"scheduler_lock:{lock_name}", "1", ex=ttl_seconds, nx=True)
        return bool(ok)
    except Exception as e:
        logger.warning(f"调度锁 Redis 故障，fail-closed 跳过本轮任务 {lock_name}: {e}")
        return False


async def clean_expired_cache():
    if not await _acquire_lock("clean_cache"):
        return
    async with AsyncSessionLocal() as db:
        try:
            result = await db.execute(delete(ResultCache).where(ResultCache.expire_at < datetime.now()))
            await db.commit()
            logger.info(f"清理过期缓存: {result.rowcount} 条")
        except Exception as e:
            logger.error(f"清理过期缓存失败: {e}")
            await db.rollback()


async def close_expired_orders():
    if not await _acquire_lock("close_orders", 300):
        return
    async with AsyncSessionLocal() as db:
        try:
            timeout = datetime.now() - timedelta(minutes=settings.ORDER_TIMEOUT_MINUTES)
            result = await db.execute(update(Order).where(
                Order.status == "pending", Order.created_at < timeout).values(status="expired"))
            await db.commit()
            if result.rowcount > 0:
                logger.info(f"关闭超时订单: {result.rowcount} 个")
        except Exception as e:
            logger.error(f"关闭超时订单失败: {e}")
            await db.rollback()


async def auto_refund_failed_reports():
    """失败报告自动退款（failed 超 10 分钟）。T17：退款成功后同步报告状态为 refunded"""
    if not await _acquire_lock("auto_refund"):
        return
    async with AsyncSessionLocal() as db:
        try:
            threshold = datetime.now() - timedelta(minutes=10)
            reports = (await db.execute(select(Report).where(
                Report.status == "failed", Report.retry_count < 99,
                Report.updated_at < threshold))).scalars().all()
            for report in reports:
                order = (await db.execute(select(Order).where(Order.id == report.order_id))).scalar_one_or_none()
                if not order or order.status != "completed":
                    report.retry_count = 99
                    continue
                # L23：本任务是 4 条退款路径中唯一**完全没有**校验资金流入的一条，
                # 却是卡券兑换单与会员 0 元解读单都会走到的路径（两者都会建 Report）。
                # 少了这道判断时：报告生成失败 → 本任务对一笔 0 元订单发起退款 →
                # 模拟支付模式下 apply_refund 直接判成功 → revoke_refunded_order
                # 撤销该订单下 available 的权益，而卡券早已 used 无法重兑，
                # 用户既没拿回钱、也永久失去已兑换的商品（系统内无恢复路径）。
                # 真实渠道下则是对不存在的商户单号发起退款、重试 3 次后转人工告警。
                # 处置与 ②④ 两条路径一致：直接终结该报告，不打支付平台、不动权益。
                # 报告仍是 failed，order 仍是 completed —— 该订单的权益来源与卡券
                # 状态都原样保留，客服可据此重新生成报告或另行补偿。
                if not has_real_payment(order):
                    report.retry_count = 99
                    logger.warning(
                        f"失败报告 {report.id} 跳过自动退款：订单 {order.order_no} "
                        f"无真实资金流入（{no_payment_reason(order)}），"
                        f"pay_channel={order.pay_channel} amount={order.amount}")
                    continue
                # 必须用 scalars().first()：refunds.order_id 只有普通索引、没有唯一约束，
                # 同一订单允许多条退款单（用户申请→平台失败→订单还原 completed→再次申请）。
                # 原实现用 scalar_one_or_none()，命中两行即抛 MultipleResultsFound，
                # 异常被外层 except 吞掉后 rollback，本轮所有失败报告的自动退款一起回滚——
                # 用户付了钱、报告生成失败，却永远等不到自动退款。
                existing = (await db.execute(select(Refund).where(
                    Refund.order_id == order.id,
                    Refund.status.in_(["pending_refund", "failed", "processing"])))).scalars().first()
                if existing:
                    report.retry_count = 99
                    continue
                # 抢占订单：各个定时任务各持自己的调度锁，彼此之间并不互斥（自动退款与
                # 退款重试可能同时扫到同一笔单）；用户也可能正好在同一瞬间自助退款。
                # 不抢占就会各自新建退款单、各向支付平台发起一笔真实退款。
                # 与 api/order.py 用户端退款同一护栏。
                claimed = (await db.execute(
                    update(Order).where(Order.id == order.id, Order.status == "completed")
                    .values(status="refund_pending"))).rowcount
                if not claimed:
                    report.retry_count = 99
                    logger.info(f"报告 {report.id} 自动退款跳过：订单 {order.order_no} 已被其他路径抢占")
                    continue
                refund_no = gen_refund_no()
                refund = Refund(order_id=order.id, user_id=order.user_id,
                                reason="报告生成失败，自动退款", status="pending_refund",
                                refund_no=refund_no)
                db.add(refund)
                await db.flush()
                # V-2：退款单号在入库时即预生成并原样传给平台。此前调用 apply_refund 时不传
                # refund_no，由平台内部临时生成——若进程在拿到结果前崩溃，Refund 行上就是空单号，
                # 后续 retry_failed_refunds 重试时会再生成一个新单号，向支付平台发起第二笔真实退款。
                # 预生成后，同一条退款单的任何重试路径都复用同一个 out_refund_no，
                # 微信/支付宝对重复单号幂等返回已有结果，杜绝“同订单二次真实退款”。
                result = await apply_refund(
                    order_no=order.order_no, pay_trade_no=order.pay_trade_no or "",
                    amount=float(order.amount), reason="报告生成失败",
                    channel=order.pay_channel, order_amount=float(order.amount),
                    refund_no=refund_no)
                refund.refund_no = result.refund_no or refund_no
                if result.ok:
                    refund.status = "refunded"
                    order.status = "refunded"
                    report.status = "refunded"  # T17
                    await revoke_refunded_order(db, order)
                elif result.status == "processing":
                    refund.status = "processing"
                    order.status = "refund_pending"
                else:
                    refund.status = "failed"
                    refund.fail_reason = result.msg or "自动退款调用失败"
                    # 平台未受理：还原抢占时置的 refund_pending，交给 retry_failed_refunds 继续推进。
                    # 同样必须用 Core UPDATE，ORM 赋值不会生成 UPDATE（内存值仍是 completed）。
                    await db.execute(update(Order).where(
                        Order.id == order.id, Order.status == "refund_pending").values(status="completed"))
                report.retry_count = 99
            await db.commit()
            if reports:
                logger.info(f"失败报告自动退款处理: {len(reports)} 个")
        except Exception as e:
            logger.error(f"失败报告自动退款失败: {e}", exc_info=True)
            await db.rollback()


async def retry_failed_refunds():
    """退款失败重试（最多3次）。T6：达到上限记录 error 级别告警日志，等待人工介入"""
    if not await _acquire_lock("retry_refund"):
        return
    async with AsyncSessionLocal() as db:
        try:
            refunds = (await db.execute(
                select(Refund).where(Refund.status == "failed", Refund.retry_count < 3))).scalars().all()
            exhausted = (await db.execute(
                select(Refund).where(Refund.status == "failed", Refund.retry_count >= 3))).scalars().all()
            # T6：重试耗尽的退款单告警（每次运行只告警一次/条，日志可被监控采集）
            for r in exhausted:
                logger.error(f"[退款告警] 退款单 id={r.id} order_id={r.order_id} 已重试3次仍失败，"
                             f"原因={r.fail_reason}，需人工在支付平台核查处理")
            for refund in refunds:
                order = (await db.execute(select(Order).where(Order.id == refund.order_id))).scalar_one_or_none()
                if not order:
                    continue
                # 只重试「钱确实还没退出去」的订单。原实现不看订单状态就再调一次平台退款接口：
                # 用户自助退款失败后订单被还原为 completed，管理员随后兜底退款成功、订单已是
                # refunded，这条遗留的 failed 退款单仍会被本任务捡起来再退一次——二次真实退款。
                # 卡券兑换单（pay_channel='card'）不存在真实资金流，任何退款单都是误建；
                # 一旦重试成功同样会触发 revoke_refunded_order 撤销用户权益，而卡券已是
                # used 无法重兑 —— 用户白丢权益。直接终结该退款单，不再打支付平台。
                # L23：收紧为统一判定。原实现只认卡券单（pay_channel='card'），
                # 漏掉了同类「无真实资金流入」的订单——最典型的是会员期内 ensure-report
                # 产生的 0 元解读单（pay_channel='member', amount=0）。这类订单一旦遗留了
                # failed 退款单被本任务重试成功，同样会 revoke_refunded_order 撤销用户权益，
                # 与卡券单是同一个结局。has_real_payment 同时覆盖金额<=0 与全部无资金渠道。
                if not has_real_payment(order):
                    refund.retry_count = 3
                    refund.fail_reason = no_payment_reason(order)
                    logger.warning(
                        f"退款单 {refund.id} 跳过重试：订单 {order.order_no} "
                        f"无真实资金流入（{refund.fail_reason}）")
                    continue
                if order.status not in ("completed", "refund_pending"):
                    refund.retry_count = 3
                    refund.fail_reason = f"订单状态为{order.status}，无需重试退款"
                    logger.info(f"退款单 {refund.id} 跳过重试：订单 {order.order_no} 状态={order.status}")
                    continue
                # 同一订单存在其他在途/已成功的退款单时也必须停手：refunds.order_id 没有唯一
                # 约束，一个订单可以有多条退款单，只按 refund.status=='failed' 捞取会把
                # 「另一条已成功/正在处理」的订单再退一次。
                dup = (await db.execute(select(Refund.id).where(
                    Refund.order_id == order.id, Refund.id != refund.id,
                    Refund.status.in_(["refunded", "processing", "pending_refund"])))).first()
                if dup:
                    refund.retry_count = 3
                    refund.fail_reason = "同订单已有其他退款单在处理，停止重试"
                    logger.info(f"退款单 {refund.id} 跳过重试：订单 {order.order_no} 已有退款单 id={dup[0]}")
                    continue
                # 抢占订单（仅 completed 时）：自动退款与退款重试是两条任务链，各自的调度锁
                # 不互斥，可能同时扫到同一笔单；用户也可能正好在同一瞬间自助退款。
                # 已是 refund_pending 时不做同值 CAS——MySQL 的 affected_rows 只统计
                # 「值真正改变的行」，同值 UPDATE 恒返回 0，会让重试永久失效。
                if order.status == "completed":
                    claimed = (await db.execute(
                        update(Order).where(Order.id == order.id, Order.status == "completed")
                        .values(status="refund_pending"))).rowcount
                    if not claimed:
                        logger.info(f"退款单 {refund.id} 跳过重试：订单 {order.order_no} 已被其他路径抢占")
                        continue
                result = await apply_refund(
                    order_no=order.order_no, pay_trade_no=order.pay_trade_no or "",
                    amount=float(order.amount), reason=refund.reason, channel=order.pay_channel,
                    refund_no=refund.refund_no or None, order_amount=float(order.amount))
                refund.retry_count += 1
                if result.ok:
                    refund.status = "refunded"
                    refund.fail_reason = None
                    order.status = "refunded"
                    await revoke_refunded_order(db, order)
                elif result.status == "processing":
                    refund.status = "processing"
                    order.status = "refund_pending"
                else:
                    refund.fail_reason = f"第{refund.retry_count}次重试失败: {result.msg or ''}"
                    # 平台仍未受理：把上面抢占时置的 refund_pending 还原为 completed，
                    # 否则订单永久卡在“退款中”，用户看不到已完成订单、下一轮重试也会被状态判断跳过。
                    # 必须用 Core UPDATE：ORM 实例内存里的 status 仍是抢占前的 completed，
                    # 赋相同值不会生成 UPDATE（与 api/order.py 用户端退款同一处理）。
                    await db.execute(update(Order).where(
                        Order.id == order.id, Order.status == "refund_pending").values(status="completed"))
            await db.commit()
            if refunds:
                logger.info(f"退款失败重试: {len(refunds)} 个")
        except Exception as e:
            logger.error(f"退款失败重试异常: {e}", exc_info=True)
            await db.rollback()


async def settle_commissions():
    if not await _acquire_lock("settle_commission"):
        return
    async with AsyncSessionLocal() as db:
        try:
            count = await settle_due_commissions(db)
            await db.commit()
            if count:
                logger.info(f"佣金结算完成: {count} 笔")
        except Exception as e:
            logger.error(f"佣金结算失败: {e}", exc_info=True)
            await db.rollback()


async def verify_paid_users_and_promote():
    """V1.3 第十六~十八条：验证付费用户过7天退款期转正（终身只计一次）
    + 达门槛后待升等级于次日0点落地。与佣金结算同频（每30分钟）。"""
    if not await _acquire_lock("verify_promote"):
        return
    async with AsyncSessionLocal() as db:
        try:
            verified = await promote_verified_users(db)
            promoted = await apply_pending_promotions(db)
            await db.commit()
            if verified or promoted:
                logger.info(f"验证付费用户转正 {verified} 人，等级生效 {promoted} 人")
        except Exception as e:
            logger.error(f"验证付费用户/晋升处理失败: {e}", exc_info=True)
            await db.rollback()


async def monthly_reward_settlement():
    """V1.3 第二十九条：次月 8 号 0-6 点统一结算上月——按最终档位重算阶梯差额一次性补发，
    并发放排行榜奖励。先跑一遍 T+7 结算，确保上月最后一日订单（T+7 恰在本日 0 点到期）
    已入账，再按最终月度总金额重核，避免阶梯档位漏算。"""
    if not await _acquire_lock("monthly_settle"):
        return
    async with AsyncSessionLocal() as db:
        try:
            await settle_due_commissions(db)
            await db.commit()
        except Exception as e:
            logger.error(f"月度结算前置 T+7 结算失败: {e}", exc_info=True)
            await db.rollback()
            return
    async with AsyncSessionLocal() as db:
        try:
            month = last_month_key()
            result = await settle_month(db, month)
            await db.commit()
            if result.get("distributors"):
                logger.info(f"月度结算[{month}]: {result['distributors']} 人，"
                            f"阶梯补发 {result['ladder_adjust']:.2f}，排行奖励 {result['rank_reward']:.2f}")
        except Exception as e:
            logger.error(f"月度排行榜/阶梯结算失败: {e}", exc_info=True)
            await db.rollback()


async def expire_entitlements():
    if not await _acquire_lock("expire_entitlement"):
        return
    async with AsyncSessionLocal() as db:
        try:
            count = await expire_due_entitlements(db)
            await db.commit()
            if count:
                logger.info(f"过期权益清理: {count} 条")
        except Exception as e:
            logger.error(f"过期权益清理失败: {e}")
            await db.rollback()


async def sync_overdue_memberships():
    """M7：过期月会员 level 同步为 none，保证管理后台展示一致"""
    if not await _acquire_lock("sync_membership", 300):
        return
    async with AsyncSessionLocal() as db:
        try:
            count = await expire_overdue_memberships(db)
            await db.commit()
            if count:
                logger.info(f"过期会员状态同步: {count} 个")
        except Exception as e:
            logger.error(f"过期会员同步失败: {e}")
            await db.rollback()


async def retry_failed_commissions():
    """T5：计佣失败重试，避免佣金静默丢失"""
    if not await _acquire_lock("retry_commission", 300):
        return
    async with AsyncSessionLocal() as db:
        try:
            fails = (await db.execute(select(CommissionFailLog).where(
                CommissionFailLog.status == "pending", CommissionFailLog.retry_count < 3))).scalars().all()
            for f in fails:
                order = (await db.execute(select(Order).where(Order.id == f.order_id))).scalar_one_or_none()
                if not order or order.status != "completed":
                    f.status = "abandoned"
                    continue
                try:
                    log = await on_order_paid(db, order)
                    if log:
                        f.status = "success"
                    else:
                        # on_order_paid 返回 None 可能是不符合计佣条件，标记放弃
                        f.status = "abandoned"
                except Exception as e:
                    f.retry_count += 1
                    f.fail_reason = str(e)[:300]
                    if f.retry_count >= 3:
                        f.status = "abandoned"
                        logger.error(f"[计佣告警] 订单 {f.order_no} 计佣重试3次仍失败: {e}")
            await db.commit()
        except Exception as e:
            logger.error(f"计佣失败重试异常: {e}", exc_info=True)
            await db.rollback()


async def sync_pending_payments():
    """A2：支付主动查单 + 掉单补偿（每 2 分钟）。

    回调丢失（网络闪断/发布重启/平台重试耗尽）时用户已扣款而订单永不履约，这是纯回调
    架构的固有缺口。本任务向渠道主动查单，确认已收款则走与回调完全相同的 CAS 履约入口补发放，
    因此与回调并发到达也不会重复发放。锁 TTL 与调度间隔一致（120s）：锁不主动释放，
    TTL 大于间隔会让下一轮被误跳。Redis 故障时 fail-closed 跳过本轮，由后续轮次自然补跑。"""
    if not await _acquire_lock("pay_sync", 120):
        return
    async with AsyncSessionLocal() as db:
        try:
            stats = await sync_stuck_orders(db)
            await db.commit()
            if stats.get("scanned"):
                logger.info(f"[掉单补偿] 扫描 {stats['scanned']} 笔，补履约 {stats.get('fulfilled', 0)}，"
                            f"已履约 {stats.get('already', 0)}，渠道未答清 {stats.get('retry_later', 0)}")
            if stats.get("amount_mismatch"):
                logger.error(f"[掉单补偿告警] {stats['amount_mismatch']} 笔订单金额与渠道不符，"
                             f"已拒绝履约，需人工核查")
        except Exception as e:
            logger.error(f"支付查单补偿异常: {e}", exc_info=True)
            await db.rollback()


async def sync_processing_refunds():
    """A2 同范式（退款侧）：主动向渠道核实「退款中」的退款单，把结论拉回来落库。

    为什么必须有：退款最终结论原先只来自渠道回调，而回调会因验签配置错误、发布重启、网络
    抖动或平台重试耗尽而永远不到达——退款单就永久停在 processing，管理员既看不到「退款
    成功」也不敢重发，只能靠猜（本项目实际故障形态）。本任务向渠道主动查退款，确认成功的
    走与回调完全相同的 apply_channel_refund_status（原子 CAS + 订单守卫），因此与回调并发
    到达也不会二次回收权益。锁 TTL 与调度间隔一致，Redis 故障时 fail-closed 跳过本轮，由
    后续轮次自然补跑。与 retry_failed_refunds 分工不重叠：那个只管渠道「明确不受理」的
    failed 单重发，本任务只管渠道「已受理、结论未知」的 processing 单核实。"""
    if not settings.PAY_QUERY_ENABLED:
        return
    if not await _acquire_lock("refund_sync", 300):
        return
    async with AsyncSessionLocal() as db:
        try:
            # 只查过了冷却期的单：刚受理的退款大概率还在渠道处理中，立刻查是白跑。
            # updated_at 由每次状态写入推进，所以同一条退款单不会每轮都被重复查询。
            cutoff = datetime.now() - timedelta(minutes=3)
            refunds = (await db.execute(
                select(Refund).where(Refund.status == "processing",
                                     Refund.updated_at < cutoff)
                .order_by(Refund.id).limit(50))).scalars().all()
            checked = changed = 0
            for refund in refunds:
                if not refund.refund_no:
                    continue
                r = await query_refund(refund.refund_no, channel="wechat")
                state = r.get("state")
                checked += 1
                if state == "success":
                    await apply_channel_refund_status(db, refund, "SUCCESS", source="scheduler")
                    changed += 1
                elif state == "failed":
                    await apply_channel_refund_status(db, refund, "CLOSED", source="scheduler")
                    changed += 1
                # processing/unsupported/error：保持原状下一轮再核，绝不把「查不到」猜成失败
            await db.commit()
            if checked:
                logger.info(f"[退款主动核实] 核实 {checked} 笔，结论更新 {changed} 笔")
        except Exception as e:
            logger.error(f"退款主动核实异常: {e}", exc_info=True)
            await db.rollback()




async def daily_reconciliation():
    """A3：每日渠道对账（默认 RECONCILE_HOUR=10 点的 30 分，微信次日 09:00 生成前一日账单，
    官方建议 10:00 后拉取；错开半小时避开整点集中拉单）。
    回溯 RECONCILE_LOOKBACK_DAYS 天逐日轧账，补跑漏账；差错只入账不改账，
    仅「渠道已收款而本地未履约」会走同源 CAS 入口自动补履约。
    逐日提交已在 reconcile_recent 内部完成，这里的 commit 只是收尾兜底。"""
    if not await _acquire_lock("reconcile", 3600):
        return
    async with AsyncSessionLocal() as db:
        try:
            result = await reconcile_recent(db)
            await db.commit()
            if not result.get("skipped"):
                logger.info(f"[对账] 完成，共 {result.get('total_diffs', 0)} 条差错待人工处置")
        except Exception as e:
            logger.error(f"每日对账异常: {e}", exc_info=True)
            await db.rollback()


async def purge_ai_generation_logs():
    """A4：清理超过留存期的 AI 生成日志（每日 03:30，紧随缓存清理之后）。

    为何既要留存又要清理：《标识办法》第十一条要求生成日志留存不少于六个月，
    但日志里带 user_id 与输入摘要，属于个人信息；无限期保留反而违反《个保法》
    的最小必要与存储期限原则。两头都要站得住，就只能按明确的期限清理。

    留存天数取 max(配置, 180)：180 天是法定下限，配置写错（误填 0 或 30）不能静默
    把合规证据删干净——那是一次不可逆的删除，事后无法补回。
    分批删除：先查 id 再按 id 删，而不用 DELETE ... LIMIT：后者 MySQL 支持而
    SQLite 默认不支持（需编译期开 SQLITE_ENABLE_UPDATE_DELETE_LIMIT），
    两种方言下行为必须一致；分片也避开一次删数十万行的长事务锁表。
    单轮上限 20 万行，清不完留到次日，不把凌晨窗口拖成长任务。"""
    if not await _acquire_lock("purge_ai_log", 1800):
        return
    days = max(int(settings.AI_MARK_RETENTION_DAYS or 0), 180)
    cutoff = datetime.now() - timedelta(days=days)
    async with AsyncSessionLocal() as db:
        try:
            total = 0
            for _ in range(200):
                ids = (await db.execute(select(AiGenerationLog.id).where(
                    AiGenerationLog.created_at < cutoff).limit(1000))).scalars().all()
                if not ids:
                    break
                await db.execute(delete(AiGenerationLog).where(AiGenerationLog.id.in_(ids)))
                # 逐批提交：中途异常不会把已删的批次回滚（回滚反而会把本该清理的
                # 个人信息重新写回去）。
                await db.commit()
                total += len(ids)
            if total:
                logger.info(f"[AI标识留存] 清理超期生成日志 {total} 条（留存 {days} 天，早于 {cutoff:%Y-%m-%d}）")
        except Exception as e:
            logger.error(f"AI 生成日志清理异常: {e}", exc_info=True)
            await db.rollback()


async def alert_heartbeat():
    """B2：每日告警通道心跳（默认 09:00）。

    为何必须有：告警通道的故障形态是「静默」——机器人被移出群、钉钉安全设置从加签
    改成关键词而关键词不匹配、webhook 过期，表现都是一条告警也收不到，与「系统正常」
    完全同形。不主动自证可用，就只能等到真出资金故障时才发现通道早就断了，
    而那时损失的正是本可以第一时间知道的那几个小时。

    不加分布式互斥锁：心跳要验的是「这台进程能不能把消息发出去」。多副本各发一条、
    消息里带主机名，正好能看出是哪一副本的出网被拦了；用锁只让一个副本发，
    反而把「另一个副本发不出去」这件事永久掩盖掉。
    """
    if not settings.ALERT_HEARTBEAT_ENABLED:
        return
    try:
        from app.core.utils.alert import heartbeat
        res = await heartbeat()
        if res.get("sent"):
            logger.info(f"[告警心跳] 已发送（通道 {'/'.join(res.get('channels') or [])}）")
        elif res.get("skipped"):
            pass    # 未配置通道：install_alert_handler 与启动自检各提醒过，不重复刷日志
        else:
            # 发不出去且不是「未配置」：通道本身已断。这条 ERROR 自己也会经 Handler
            # 尝试外发（大概率同样失败），因此它只会落在容器日志里——通道断了就无法
            # 用通道报告，这是无解的最后一环；兜底靠的是运维发现「今天没收到心跳」时来查这条日志。
            logger.error(f"[告警心跳] 发送失败，告警通道可能已断: {res.get('errors')}")
    except Exception as e:
        logger.error(f"告警心跳异常: {e}", exc_info=True)


def start_scheduler():
    scheduler.add_job(clean_expired_cache, "cron", hour=3, minute=0, id="clean_cache", replace_existing=True)
    scheduler.add_job(close_expired_orders, "interval", minutes=5, id="close_orders", replace_existing=True)
    scheduler.add_job(auto_refund_failed_reports, "interval", minutes=10, id="auto_refund", replace_existing=True)
    scheduler.add_job(retry_failed_refunds, "interval", minutes=30, id="retry_refund", replace_existing=True)
    scheduler.add_job(settle_commissions, "interval", minutes=30, id="settle_commission", replace_existing=True)
    scheduler.add_job(verify_paid_users_and_promote, "interval", minutes=30, id="verify_promote", replace_existing=True)
    scheduler.add_job(monthly_reward_settlement, "cron", day=settings.DIST_MONTHLY_SETTLE_DAY,
                      hour=1, minute=0, id="monthly_settle", replace_existing=True)
    scheduler.add_job(expire_entitlements, "interval", hours=1, id="expire_entitlement", replace_existing=True)
    scheduler.add_job(sync_overdue_memberships, "interval", hours=1, id="sync_membership", replace_existing=True)
    scheduler.add_job(retry_failed_commissions, "interval", minutes=15, id="retry_commission", replace_existing=True)
    # A2：支付主动查单/掉单补偿（必须在 close_expired_orders 之外独立跑：关单只改状态，
    # 不会去渠道核实钱到底收没收）
    scheduler.add_job(sync_pending_payments, "interval", minutes=2, id="pay_sync", replace_existing=True)
    # A2 同范式（退款侧）：退款主动核实。退款结论不能只等回调——验签配置错误/发布重启/
    # 平台重试耗尽都会让回调永不到达，退款单永久停在「退款中」，后台无从判断钱退没退。
    scheduler.add_job(sync_processing_refunds, "interval", minutes=5,
                      id="refund_sync", replace_existing=True)
    # A3：每日渠道对账（资金系统的最后一道防线）
    if settings.RECONCILE_ENABLED:
        scheduler.add_job(daily_reconciliation, "cron", hour=settings.RECONCILE_HOUR, minute=30,
                          id="reconcile", replace_existing=True)
    # A4：生成日志留存期清理（法定下限 180 天，超期即属过度留存个人信息）
    scheduler.add_job(purge_ai_generation_logs, "cron", hour=3, minute=30,
                      id="purge_ai_log", replace_existing=True)
    # B2：告警通道每日心跳。放在对账之后（对账 10:30）而不与其同刻：心跳要报的是
    # 「昨日至今」的统计，早点发才能在工作日开始时就看到，而不是午后。
    if settings.ALERT_HEARTBEAT_ENABLED:
        scheduler.add_job(alert_heartbeat, "cron", hour=int(settings.ALERT_HEARTBEAT_HOUR or 0) % 24,
                          minute=0, id="alert_heartbeat", replace_existing=True)
    scheduler.start()
    logger.info("定时任务调度器已启动（v7）")
