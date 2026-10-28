"""A2：支付主动查单与掉单补偿。

背景：履约原本只有一条路径——等支付平台的异步回调（api/payment.py 的 wechat/alipay notify）。
回调会因网络闪断、服务发布重启、平台重试耗尽而全部丢失；此时用户已扣款，而订单永久停在
pending/expired，会员与权益永不发放。这是纯回调架构的固有缺口，行业内称「掉单」，
成熟支付系统的标准做法是三层兜底：异步回调 + 前端触发查单 + 定时对账/查单。本模块补上后两层
的查单部分（对账见 services/reconcile.py）。

设计要点：
1. 复用 api.payment._mark_order_paid（CAS 抢占履约权 + 金额校验 + 报告触发），绝不另写一套
   履约逻辑——两条路径的幂等口径一旦漂移，就会出现「回调补了一半、查单又补一遍」的重复发放。
2. 非请求上下文（调度任务）里 BackgroundTasks 收集的任务没人执行，这里手工 await，
   使报告生成与回调路径行为一致。
3. 只做「补履约」，不做「自动关单」：晚到支付激活 expired 订单是既有设计
   （_mark_order_paid 的 CAS 明确允许 expired → completed）；主动关单反而会把仍在收银台的
   用户挡在门外，并制造「关单后到账」这类更难处理的新差错。
4. 渠道答 unknown（超时/异常）绝不等同于 unpaid：unknown 表示「没问成」，必须下一轮继续问，
   否则一次网络抖动就会让已付款订单永久失去补偿机会。
"""
import logging
from datetime import datetime, timedelta

from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.background import BackgroundTasks

from app.config import settings
from app.core.models import Order
from app.core.utils.payment import query_payment

logger = logging.getLogger(__name__)

# 真实资金渠道。member/0 元单没有渠道流水，查不到也不该查。
_REAL_CHANNELS = ("wechat", "alipay")


async def sync_one_order(db: AsyncSession, order: Order, source: str = "scheduler",
                         background_tasks=None) -> dict:
    """对单个订单主动查单；渠道确认已收款则补履约。返回处置结果供调用方统计与告警。

    action 取值：fulfilled（本次补履约成功）/ already（此前已履约，幂等）/ noop（渠道未支付）
                / retry_later（渠道没答清，下轮再问）/ skip（渠道不可用或订单不可补偿）
                / amount_mismatch（渠道金额与订单不符，已拒绝履约，需人工核查）

    background_tasks：请求上下文传入 Starlette 的 BackgroundTasks，报告生成延到响应发出后执行；
    为 None 时（调度任务）自建一个并在此处手工 await——非请求上下文里没人替你跑这些任务，
    不 await 就等于补了状态却没生成报告。generate_report_task 只用 order_id 并自建会话，
    不依赖本函数的 db，因此延后执行是安全的。
    """
    result = await query_payment(order.order_no, order.pay_channel)
    state = result.get("state")
    if state == "unsupported":
        return {"order_no": order.order_no, "action": "skip", "reason": "channel_unavailable"}
    if state == "unknown":
        return {"order_no": order.order_no, "action": "retry_later", "state": state}
    if state != "paid":
        # 渠道明确未收款。closed/revoked/error 属于异常终态（用户支付失败、被撤销、渠道报错），
        # 本地却还挂着可补偿状态时留一条告警，便于排查「用户说付了钱」的客诉。
        if state in ("closed", "revoked", "error"):
            logger.warning(f"[掉单补偿] 渠道交易非成功态 order={order.order_no} "
                           f"local_status={order.status} channel_state={state} source={source}")
        return {"order_no": order.order_no, "action": "noop", "state": state}

    # 渠道已收款：走与回调完全相同的幂等履约入口。
    # 延迟导入：api.payment 依赖 services.fulfillment，模块级反向导入 api 层有循环风险，
    # 且调度器启动阶段无需加载 FastAPI 路由模块。
    from app.core.api.payment import _mark_order_paid

    before_status = order.status
    deferred = background_tasks is not None
    bt = background_tasks if deferred else BackgroundTasks()
    r = await _mark_order_paid(db, order, result.get("pay_trade_no"), bt,
                               amount_paid=result.get("amount"))
    if not deferred:
        for task in getattr(bt, "tasks", []):
            try:
                await task()
            except Exception as e:
                # 报告生成失败不推翻「已收款必须履约」这个结论：失败报告由
                # scheduler.auto_refund_failed_reports 兜底自动退款，此处只留痕。
                logger.error(f"[掉单补偿] 后台报告任务异常 order={order.order_no}: {e}")

    if r.get("reason") == "amount_mismatch":
        logger.error(f"[掉单补偿] 渠道金额与订单不符，已拒绝履约 order={order.order_no} "
                     f"expect={order.amount} got={result.get('amount')} —— 需人工核查是否被篡改")
        return {"order_no": order.order_no, "action": "amount_mismatch"}
    if r.get("idempotent"):
        return {"order_no": order.order_no, "action": "already", "state": state}
    if r.get("paid"):
        # WARNING 而非 INFO：每命中一条都说明回调链路丢了一次通知，是需要关注的信号。
        logger.warning(f"[掉单补偿] 回调丢失，已补履约 order={order.order_no} sku={order.sku_code} "
                       f"amount={order.amount} status_before={before_status} "
                       f"trade_no={result.get('pay_trade_no')} source={source}")
        return {"order_no": order.order_no, "action": "fulfilled"}
    return {"order_no": order.order_no, "action": "skip", "reason": r.get("reason")}


async def sync_stuck_orders(db: AsyncSession) -> dict:
    """扫描可能掉单的订单并逐笔补偿，返回统计。

    两类目标：
      1) pending 且下单已超过 PAY_QUERY_DELAY_SECONDS —— 给异步回调让路后再问，避免与回调抢单；
      2) expired 且在 PAY_QUERY_EXPIRED_WINDOW_HOURS 内 —— 已被关单任务关闭，但用户可能在关单
         前一刻付了款而回调丢失（_mark_order_paid 允许 expired → completed）。

    注意不能用 pay_url 非空来缩小范围：pay_url 只在 pay_type=redirect（微信 H5 / 支付宝 WAP）
    时写入，微信内 JSAPI 支付恒为 NULL——而 JSAPI 正是本产品的主支付路径，用它过滤会让主链路
    的掉单补偿整体失效。

    串行处理：并发查单会同时打渠道接口触发限流，且同一笔单的多条补偿路径互相竞争没有意义
    （履约权由 _mark_order_paid 的 CAS 保证唯一）。
    """
    stats = {"scanned": 0, "fulfilled": 0, "already": 0, "noop": 0,
             "retry_later": 0, "amount_mismatch": 0, "skip": 0}
    if not settings.PAY_QUERY_ENABLED:
        return stats

    now = datetime.now()
    pending_from = now - timedelta(hours=settings.PAY_QUERY_PENDING_WINDOW_HOURS)
    expired_from = now - timedelta(hours=settings.PAY_QUERY_EXPIRED_WINDOW_HOURS)
    delay_cut = now - timedelta(seconds=settings.PAY_QUERY_DELAY_SECONDS)
    # 外层下界取两个窗口中较宽的一个，否则 48 小时补偿窗口会被 2 小时的 pending 窗口截断
    window_from = min(pending_from, expired_from)

    orders = (await db.execute(
        select(Order).where(
            Order.pay_channel.in_(list(_REAL_CHANNELS)),
            Order.fulfilled_at.is_(None),
            Order.status.in_(["pending", "expired"]),
            Order.created_at >= window_from,
            or_(and_(Order.status == "pending", Order.created_at <= delay_cut),
                and_(Order.status == "expired", Order.created_at >= expired_from)),
        ).order_by(Order.created_at.asc()).limit(settings.PAY_QUERY_BATCH_SIZE)
    )).scalars().all()

    for order in orders:
        stats["scanned"] += 1
        try:
            r = await sync_one_order(db, order)
        except Exception as e:
            # 单笔异常不能中断整轮：一笔订单的渠道数据异常不该让其余掉单继续等下一轮
            logger.error(f"[掉单补偿] 处理异常 order={order.order_no}: {e}", exc_info=True)
            stats["skip"] += 1
            continue
        action = r.get("action", "skip")
        stats[action] = stats.get(action, 0) + 1
        if action == "amount_mismatch":
            # 金额不符意味着要么渠道数据异常要么订单被篡改，逐笔 ERROR 告警交人工
            logger.error(f"[掉单补偿告警] 订单金额与渠道不符 order={order.order_no}，已拒绝履约")
    return stats


async def sync_order_for_user(db: AsyncSession, order: Order, background_tasks=None) -> dict:
    """前端轮询 pay-status 时触发的单笔查单（用户视角的「我已支付，怎么还没开通」）。

    与定时任务共用 sync_one_order，因此幂等与金额校验完全一致；节流由调用方
    （api/order.py pay_status）用 Redis SETNX 完成，这里不重复限流。
    """
    if not settings.PAY_QUERY_ENABLED:
        return {"action": "skip", "reason": "disabled"}
    if order.pay_channel not in _REAL_CHANNELS or order.fulfilled_at is not None:
        return {"action": "skip", "reason": "not_queryable"}
    if order.status not in ("pending", "expired"):
        return {"action": "skip", "reason": order.status}
    return await sync_one_order(db, order, source="pay_status",
                                background_tasks=background_tasks)
