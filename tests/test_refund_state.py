"""退款状态机回归测试。

为什么先测这里：退款是资金链路上唯一「钱已经出去了还要往回追」的动作，
状态机判错方向就直接是资损——
  · 把已退款订单还原成 completed      → 权益不回收、可被再次退款（重复退款）
  · 把已成功的退款单降级为 failed      → 本地记录与渠道事实相反，且会被重试任务反复捞取
  · 在 PROCESSING 时把订单还原         → 后台显示「未退款」而钱实际已退出

只覆盖不触发 revoke_refunded_order 的分支（SUCCESS 分支会连带回收权益与冲佣，
需要完整的插件与履约环境，另行补测），
守卫类断言正是本模块最容易被后续改动悄悄破坏的部分。
"""
from decimal import Decimal

import pytest

from app.core.models import Order, Refund
from app.core.services.refund_state import apply_channel_refund_status


async def _seed(db, order_status="refund_pending", refund_status="pending_refund"):
    order = Order(order_no="T-1", user_id=1, product_name="测试商品",
                  amount=Decimal("9.90"), status=order_status)
    db.add(order)
    await db.flush()
    refund = Refund(order_id=order.id, user_id=1, refund_no="R-1",
                    reason="测试退款", status=refund_status)
    db.add(refund)
    await db.flush()
    return order, refund


async def test_closed_restores_refund_pending_to_completed(db):
    """渠道最终未退成：订单从「退款中」还原为已完成，用户看得见自己的订单。"""
    order, refund = await _seed(db)
    result = await apply_channel_refund_status(db, refund, "CLOSED", source="test")
    assert result == "failed"
    await db.refresh(order)
    assert order.status == "completed"


async def test_closed_never_resurrects_refunded_order(db):
    """资损防线一：迟到的 CLOSED 不得把已退款订单写回 completed。

    否则权益不回收，且该订单可被再次发起退款——同一笔钱退两次。
    """
    order, refund = await _seed(db, order_status="refunded")
    await apply_channel_refund_status(db, refund, "CLOSED", source="test")
    await db.refresh(order)
    assert order.status == "refunded", "已退款订单被还原成 completed，将导致重复退款"


async def test_closed_never_downgrades_successful_refund(db):
    """资损防线二：已成功的退款单不得被迟到的 CLOSED/ABNORMAL 降级为 failed。

    降级后本地记录与渠道事实相反，且 retry_failed_refunds 会把它
    当成待重试的失败单反复捞取。
    """
    _order, refund = await _seed(db, refund_status="refunded")
    result = await apply_channel_refund_status(db, refund, "CLOSED", source="test")
    assert result == "failed"  # 返回分支名，不代表落库状态
    await db.refresh(refund)
    assert refund.status == "refunded", "已成功的退款单被降级为 failed"


async def test_processing_keeps_order_untouched(db):
    """PROCESSING 表示渠道已受理、钱正在退，此时绝不能还原订单——
    「显示未退款而钱已退出」比没有展示更危险。"""
    order, refund = await _seed(db)
    result = await apply_channel_refund_status(db, refund, "PROCESSING", source="test")
    assert result == "processing"
    await db.refresh(order)
    assert order.status == "refund_pending"
    await db.refresh(refund)
    assert refund.status == "processing"


async def test_processing_does_not_overwrite_terminal_refund(db):
    """已终态的退款单不再被中间态推进。"""
    _order, refund = await _seed(db, refund_status="refunded")
    await apply_channel_refund_status(db, refund, "PROCESSING", source="test")
    await db.refresh(refund)
    assert refund.status == "refunded"


@pytest.mark.parametrize("raw_status", ["closed", "Closed", "CLOSED", "abnormal"])
async def test_status_matching_is_case_insensitive(db, raw_status):
    """渠道状态大小写不敏感，避免把同一状态解释成两种结果。"""
    order, refund = await _seed(db)
    result = await apply_channel_refund_status(db, refund, raw_status, source="test")
    assert result == "failed"
    await db.refresh(order)
    assert order.status == "completed"
