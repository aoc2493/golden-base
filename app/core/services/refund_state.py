"""退款状态机：把渠道退款结论落到本地退款单与订单。

退款状态机单独成模块：退款结论有两个来源——①渠道回调推送（api/payment.py 的
_handle_wechat_refund）；②后台「同步渠道状态」与定时主动查退款（admin 同步接口、
scheduler.sync_processing_refunds）。两处若各写一份状态迁移，迟早出现「回调说成功、
查询说失败」的口径分裂：同一个渠道状态被解释成两种本地结果，退款台账与订单状态
互相打架。本模块是这条状态机的唯一实现，两条链路都调用它。
"""
import logging

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.models import Order, Refund
from app.core.services.fulfillment import revoke_refunded_order

logger = logging.getLogger(__name__)

# 渠道退款状态分组：与 utils/payment.REFUND_STATUS_MAP 同口径，只认渠道原始值。
REFUND_SUCCESS = "SUCCESS"
REFUND_FAILED = ("CLOSED", "ABNORMAL")


async def apply_channel_refund_status(db: AsyncSession, refund: Refund,
                                      channel_status: str,
                                      source: str = "callback") -> str:
    """据渠道状态更新退款单与订单，返回落库后的本地退款单状态。

    channel_status 为渠道原始状态（大小写不敏感）：
      SUCCESS         -> 退款成功：退款单 refunded、订单 refunded、回收权益/冲佣
      CLOSED/ABNORMAL -> 渠道最终未退成：退款单 failed、订单 refund_pending 还原 completed
      PROCESSING/其它 -> 中间态：只把 pending_refund 推进为 processing，订单保持不动
    source 仅用于日志定位调用方（wechat_callback / admin_sync / scheduler）。
    """
    st = str(channel_status or "").upper()
    order = (await db.execute(
        select(Order).where(Order.id == refund.order_id))).scalar_one_or_none()

    if st == REFUND_SUCCESS:
        # 并发护栏（逐字保留自原微信回调实现）：退款回调/定时查询都可能重复投递、重复执行。
        # 原「if refund.status != 'refunded'」是内存闸，两条 SUCCESS 并发时各自 session 都读到
        # 非 refunded 而双双穿过，revoke_refunded_order 执行两次——会员天数二次扣减、佣金二次
        # 冲回（对用户与平台都是错误的资金动作）。改用原子 CAS 抢占「置 refunded」的权利：
        # WHERE status != 'refunded' 使已 refunded 的行不再匹配（rowcount=0），唯有抢到的那条
        # 链路执行回收，与 _mark_order_paid 履约抢占同一范式。
        claimed = (await db.execute(
            update(Refund).where(Refund.id == refund.id, Refund.status != "refunded")
            .values(status="refunded")
            .execution_options(synchronize_session=False))).rowcount
        if not claimed:
            # 同一条退款单的重复投递：上一次已置 refunded，幂等返回
            return "refunded"
        # 订单级独占：refunds.order_id 无唯一约束，同一订单可以有多条退款单（用户申请→平台
        # 拒绝→订单还原 completed→再次申请/管理员兜底）。只 CAS 退款单行时，两条不同退款单的
        # SUCCESS（重复申请、或乱序重投）会各自抢占成功，revoke_refunded_order 被执行两次
        # ——会员天数二次扣减、佣金二次冲回。与 _mark_order_paid 抢占履约权同一范式：
        # 只有把订单翻转为 refunded 的那条链路执行回收。
        if order:
            revoked = (await db.execute(
                update(Order).where(Order.id == order.id, Order.status != "refunded")
                .values(status="refunded", active_key=None)
                .execution_options(synchronize_session=False))).rowcount
            if revoked:
                # 刷新携带 CAS 写入的 status，revoke 内部会按订单状态联动发票与报告
                await db.refresh(order)
                warn = await revoke_refunded_order(db, order)
                if warn:
                    logger.error(f"退款权益回收异常 order={order.order_no}: {warn}")
        await db.flush()
        logger.info(f"退款成功已落库 order={order.order_no if order else refund.order_id} "
                    f"refund_no={refund.refund_no} source={source}")
        return "refunded"
    if st in REFUND_FAILED:
        # CLOSED / ABNORMAL：平台最终未退成，退款单标记失败，订单从 refund_pending 还原
        # completed。用 Core UPDATE 还原订单状态：ORM 实例内存值可能仍是 completed，直接赋同值
        # 不生成 UPDATE。WHERE 带 status='refund_pending' 守卫：避免与并发/滞后的 SUCCESS 竞态时
        # 把已 refunded 的订单错误还原成 completed（与 scheduler 自动退款/退款重试的还原守卫同一
        # 口径）。退款单侧同样必须带 status != 'refunded' 守卫，不能直接给 ORM 实例赋 failed：
        # 平台重投/乱序送达时，同一退款单可能先收到 SUCCESS、再收到迟到的 CLOSED/ABNORMAL，
        # 无条件覆盖会把已成功的退款单降级为 failed——本地记录与渠道事实相反，且
        # retry_failed_refunds 会把它当成待重试的失败单反复捞取。条件 UPDATE 使已成功的行不
        # 匹配，天然幂等。
        await db.execute(
            update(Refund).where(Refund.id == refund.id, Refund.status != "refunded")
            .values(status="failed", fail_reason=f"渠道退款状态 {st}"[:200])
            .execution_options(synchronize_session=False))
        if order and order.status == "refund_pending":
            await db.execute(update(Order).where(
                Order.id == order.id, Order.status == "refund_pending")
                .values(status="completed", active_key=None))
        await db.flush()
        logger.warning(f"退款被渠道判失败 order={order.order_no if order else refund.order_id} "
                       f"refund_no={refund.refund_no} channel_status={st} source={source}")
        return "failed"

    # PROCESSING 或未知中间态：只把「待退款」推进为「退款中」，订单保持 refund_pending。
    # 绝不在此还原订单：PROCESSING 表示渠道已受理、款正在退，把订单还原成 completed 会让后台
    # 显示「未退款」而钱实际已退出——与事实相反的展示比没有展示更危险。
    await db.execute(
        update(Refund).where(Refund.id == refund.id, Refund.status == "pending_refund")
        .values(status="processing")
        .execution_options(synchronize_session=False))
    await db.flush()
    return "processing"
