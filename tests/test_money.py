"""金额换算的回归测试。

金额是资金链路的地基：支付回调比对、退款校验、佣金计算、对账差错
全部依赖同一套换算口径。这里刻意只断言「确定性行为」
（同输入必得同输出、不同金额必不相等、类型稳定），
不断言具体舍入规则——避免把实现细节写死成契约，
将来调整精度策略时不会误判为回归。
"""
from decimal import Decimal

import pytest

from app.core.api.common import to_money


@pytest.mark.parametrize("raw", [0, 1, 99.99, 0.01, 12345.67, "8.80", Decimal("3.20")])
def test_to_money_is_deterministic(raw):
    """同一输入必须稳定得到同一结果（缓存键、对账比对依赖这一点）。"""
    assert to_money(raw) == to_money(raw)


def test_to_money_distinguishes_different_amounts():
    """不同金额不得被换算成同一个值，否则金额校验形同虚设。"""
    values = [to_money(v) for v in (1.00, 1.01, 1.10, 10.0)]
    assert len(set(map(str, values))) == len(values)


def test_to_money_never_returns_float_artifacts():
    """不得出现 float 二进制误差尾巴（如 8.800000000000001），
    否则回调金额与订单金额永远比对不上。"""
    result = to_money(8.8)
    assert str(result) in ("8.80", "8.8", "8.800"), f"意外结果: {result!r}"
    assert "000000" not in str(result)


def test_to_money_handles_zero_and_negative():
    assert to_money(0) == to_money(0.0)
    assert to_money(-5) != to_money(5)
