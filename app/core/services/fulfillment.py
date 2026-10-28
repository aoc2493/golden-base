# -*- coding: utf-8 -*-
"""统一履约服务 —— 通用底盘，零业务词。

按 product_type 交付：
  membership 会员天数 / single 单次内容 / tool_day 按天工具 / report 报告。
单次内容的「业务键 biz_key 怎么算、要不要后台生成」由插件 on_paid 钩子决定，
本模块只负责：发权益、自动发卡、计佣（失败落表重试）、标记履约时间。

退款回收 revoke_refunded_order 是全部退款路径的唯一共享钩子：
  回收权益/会员、冲回佣金、报告置 refunded+软删、销毁凭证卡、发票联动，
  并调用插件 on_refund 处理业务特有回收。
"""
import json
import logging
from datetime import datetime, timedelta
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.models import Order, Report, CommissionFailLog
from app.core.services import membership as membership_svc
from app.core.services import entitlement as ent_svc
from app.core.services import distribution as dist_svc
from app.core.services import invoice as invoice_svc
from app.core.services import card as card_svc
from app.core.plugin_contract import DELIVERY_REPORT

logger = logging.getLogger(__name__)


def _registry():
    from app.plugins import registry
    return registry


def _load_dict(val):
    if isinstance(val, dict):
        return val
    if isinstance(val, str) and val:
        try:
            return json.loads(val)
        except json.JSONDecodeError:
            return {}
    return {}


def order_delivers_report(order) -> bool:
    """该订单的交付物是否为 reports 表中的一份报告（决定 L21 自愈是否补触发）。

    完全由能力的 delivery 形态决定：cap.delivery == REPORT 即产报告；
    会员 0 元解读单（member_view_sku）同样能经 cap_by_sku 命中其能力。
    未注册 SKU 保守按报告处理（不因漏注册而阻断自愈）。
    """
    ptype = order.product_type or ("report" if order.product_id else "")
    if ptype == "report":
        return True
    if ptype != "single":
        # membership 交付会员天数、tool_day 交付当日轻工具，都不产报告
        return False
    _, cap = _registry().cap_by_sku(order.sku_code)
    if cap is None:
        return True
    return cap.delivery == DELIVERY_REPORT


async def fulfill_paid_order(db: AsyncSession, order: Order) -> dict:
    if order.fulfilled_at is not None:
        return {"fulfilled": False, "need_report_task": False}
    ptype = order.product_type or ("report" if order.product_id else "")
    biz = _load_dict(order.biz_data)
    need_report_task = False

    if ptype == "membership":
        await membership_svc.grant_membership(
            db, order.user_id, order.sku_code, order.order_no, order_id=order.id)
    elif ptype == "single":
        entry, cap = _registry().cap_by_sku(order.sku_code)
        if entry is None or cap is None:
            # 未注册 SKU 兜底：按 SKU 自身为 feature 发通用权益，不触发报告
            logger.warning(f"履约遇到未注册 SKU，按通用权益发放 order_id={order.id} "
                           f"sku={order.sku_code}")
            await ent_svc.grant_entitlement(
                db, order.user_id, feature=order.sku_code, order_id=order.id,
                sku_code=order.sku_code, biz_key=biz.get("biz_key"))
        else:
            # 业务键与是否需要后台生成由插件钩子给出
            paid = await entry.service.on_paid(cap, order, db)
            await ent_svc.grant_entitlement(
                db, order.user_id, feature=cap.code, order_id=order.id,
                sku_code=order.sku_code, biz_key=paid.biz_key)
            need_report_task = paid.need_report_task
    elif ptype == "tool_day":
        # biz_data 由客户端提交，date 可被篡改为非法格式；非法即回退当天，保证履约必然完成。
        day = str(biz.get("date") or "").strip()
        try:
            day_start = datetime.strptime(day, "%Y-%m-%d") if day else datetime.now()
        except ValueError:
            logger.warning(f"tool_day 日期格式非法，回退当天 order_id={order.id} date={day!r}")
            day_start = datetime.now()
        day = day_start.strftime("%Y-%m-%d")   # biz_key 与权益校验口径统一
        expire = day_start.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
        await ent_svc.grant_entitlement(
            db, order.user_id, feature=order.sku_code, order_id=order.id,
            sku_code=order.sku_code, biz_key=day, expire_at=expire)
    elif ptype == "report":
        # 唯一约束兜底，重复履约不重复建报告；用 SAVEPOINT 避免回滚调用方已写的订单状态。
        try:
            async with db.begin_nested():
                db.add(Report(order_id=order.id, user_id=order.user_id, status="generating"))
        except IntegrityError:
            logger.info(f"报告已存在，幂等跳过重复创建 order_id={order.id}")
        need_report_task = True

    # 支付订单自动发卡（付款=买卡，生成即自动使用；退款时由 revoke_refunded_order 销毁）。
    # 发卡失败只告警不阻断履约——权益/会员才是交付本体，卡券缺失可人工补发。
    try:
        await card_svc.auto_issue_for_order(db, order)
    except Exception as e:
        logger.error(f"支付订单自动发卡失败 order_id={order.id}: {e}", exc_info=True)

    # T5：计佣失败落失败表，定时任务重试
    try:
        await dist_svc.on_order_paid(db, order)
    except Exception as e:
        logger.error(f"计佣失败 order_id={order.id}: {e}", exc_info=True)
        try:
            exist = (await db.execute(select(CommissionFailLog).where(
                CommissionFailLog.order_id == order.id))).scalars().first()
            if not exist:
                db.add(CommissionFailLog(order_id=order.id, order_no=order.order_no,
                                         fail_reason=str(e)[:300], status="pending"))
                await db.flush()
        except Exception as e2:
            logger.error(f"计佣失败记录落库异常 order_id={order.id}: {e2}")

    order.fulfilled_at = datetime.now()
    await db.flush()
    return {"fulfilled": True, "need_report_task": need_report_task}


async def revoke_refunded_order(db: AsyncSession, order: Order) -> str:
    """退款成功后回收权益、冲回佣金、报告置 refunded+软删、销卡、发票联动。
    返回空串表示成功；非空串为回收过程中的异常描述（调用方需告警，不能假装成功）。"""
    ptype = order.product_type or ""
    warns = []
    registry = _registry()
    try:
        if ptype == "membership":
            await membership_svc.rollback_membership(
                db, order.user_id, order.sku_code, order_id=order.id)
        elif ptype in ("single", "tool_day"):
            await ent_svc.revoke_by_order(db, order.id)
            # 插件特有回收（report 为 no-op）
            entry, cap = registry.cap_by_sku(order.sku_code)
            if entry and cap:
                maybe = entry.service.on_refund(cap, order, db)
                if maybe is not None and hasattr(maybe, "__await__"):
                    await maybe
        elif ptype == "timepass":
            # 时长卡：撤掉本单贡献段并把其后叠加段前移（见 entitlement.revoke_timepass_by_order）
            await ent_svc.revoke_timepass_by_order(db, order.id)
    except Exception as e:
        logger.error(f"退款回收会员/权益失败 order_id={order.id}: {e}", exc_info=True)
        warns.append(f"权益回收失败: {e}")
    try:
        await dist_svc.on_order_refund(db, order)
        await db.flush()
    except Exception as e:
        logger.error(f"退款冲回佣金失败 order_id={order.id}: {e}", exc_info=True)
        warns.append(f"佣金冲回失败: {e}")
    # 报告随退款置 refunded 并软删（coalesce 保留用户自删时间戳；正文保留以支持退款兜底还原）。
    try:
        await db.execute(update(Report).where(Report.order_id == order.id).values(
            status="refunded",
            deleted_at=func.coalesce(Report.deleted_at, datetime.now())))
    except Exception as e:
        logger.error(f"退款标记报告状态失败 order_id={order.id}: {e}", exc_info=True)
        warns.append(f"报告状态回收失败: {e}")
    # 退款=销卡：销毁该订单自动生成的购买凭证卡。
    try:
        destroyed = await card_svc.destroy_by_order(db, order.order_no)
        if destroyed:
            logger.info(f"退款销毁购买凭证卡 order_no={order.order_no} count={destroyed}")
    except Exception as e:
        logger.error(f"退款销毁卡券失败 order_id={order.id}: {e}", exc_info=True)
        warns.append(f"卡券销毁失败: {e}")
    # 发票联动：交易不存在却仍开票属虚开，已开须红冲；失败不回滚退款。
    try:
        inv_warn = await invoice_svc.on_order_refunded(db, order)
        if inv_warn:
            warns.append(inv_warn)
    except Exception as e:
        logger.error(f"退款联动发票失败 order_id={order.id}: {e}", exc_info=True)
        warns.append(f"发票联动失败: {e}")
    return "；".join(warns)
