"""支付履约的守卫分支回归测试。

只覆盖 fulfill_paid_order 之前的闸门——这是「钱还没有发出去」的最后一道防线：
  · 已退款订单仍被履约        → 用户既拿到退款又拿到权益（双向资损）
  · 回调金额与订单不符仍履约  → 篡改金额即可白送权益
  · 已履约订单重复履约        → 会员二次顺延、权益重复发放、佣金重复计

履约成功分支（CAS 抢占后真正发放会员/权益/报告/计佣）依赖更完整的环境，
另行补测；这里的守卫一旦失效，损失比履约失败更大，故优先覆盖。
"""
from datetime import datetime
from decimal import Decimal

import pytest
from fastapi import BackgroundTasks

from app.core.api.common import to_money
from app.core.api.payment import _mark_order_paid
from app.core.models import Order


async def _make_order(db, status="pending", amount="39.90"):
    order = Order(order_no="P-1", user_id=1, product_name="测试商品",
                  amount=Decimal(amount), status=status)
    db.add(order)
    await db.flush()
    return order


async def test_refunded_order_is_never_fulfilled(db):
    """已退款订单不得再履约：否则用户既拿到退款又拿到权益。"""
    order = await _make_order(db, status="refunded")
    result = await _mark_order_paid(db, order, "TRADE-1", BackgroundTasks(),
                                    amount_paid=Decimal("39.90"))
    assert result.get("paid") is False
    assert result.get("reason") == "refunded"
    await db.refresh(order)
    assert order.status == "refunded"


async def test_amount_mismatch_is_rejected(db):
    """回调金额与订单不符必须拒绝履约——否则篡改金额就能白送权益。"""
    order = await _make_order(db, amount="39.90")
    result = await _mark_order_paid(db, order, "TRADE-1", BackgroundTasks(),
                                    amount_paid=Decimal("1.00"))
    assert result.get("paid") is False
    assert result.get("reason") == "amount_mismatch"
    await db.refresh(order)
    assert order.status == "pending", "金额不符却推进了订单状态"


async def test_already_fulfilled_is_idempotent(db):
    """已履约订单的重复回调必须幂等返回，不再发放一次。"""
    order = await _make_order(db)
    order.fulfilled_at = datetime.now()
    await db.flush()
    result = await _mark_order_paid(db, order, "TRADE-1", BackgroundTasks(),
                                    amount_paid=Decimal("39.90"))
    assert result.get("idempotent") is True


async def test_absent_amount_skips_comparison(db):
    """回调未携带金额时不做比对（避免误拒真实回调），但其余守卫照常生效。"""
    order = await _make_order(db, status="refunded")
    result = await _mark_order_paid(db, order, "TRADE-1", BackgroundTasks())
    assert result.get("reason") == "refunded"


@pytest.mark.parametrize("paid", ["39.90", "39.9", Decimal("39.90"), 39.9])
def test_amount_comparison_tolerates_representations(paid):
    """金额的不同表示（字符串/Decimal/float/尾随零）必须判为一致，
    否则真实回调会因格式差异被误拒（_mark_order_paid 的校验就建立在 to_money 上）。"""
    assert to_money(paid) == to_money(Decimal("39.90"))
    # 同一比较口径下，真实的金额篡改仍必须判为不一致
    assert to_money("1.00") != to_money(Decimal("39.90"))
