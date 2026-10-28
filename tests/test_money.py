"""金额换算的回归测试。

金额是资金链路的地基：支付回调比对、退款校验、佣金计算、对账差错全部依赖同一套换算口径。
本文件把这套口径钉成可执行的契约——每条断言都写出期望值，因为「to_money(x) == to_money(x)」
这类自反断言恒真，删掉整个函数实现也不会变红，等于没有测试。
"""
from decimal import Decimal

import pytest

from app.core.api.common import to_money


@pytest.mark.parametrize("raw, expect", [
    (0, Decimal("0.00")),
    (1, Decimal("1.00")),
    (99.99, Decimal("99.99")),
    (0.01, Decimal("0.01")),
    (12345.67, Decimal("12345.67")),
    ("8.80", Decimal("8.80")),
    ("39.9", Decimal("39.90")),
    ("0", Decimal("0.00")),
    (None, Decimal("0")),
])
def test_to_money_normalizes_to_two_decimals(raw, expect):
    """int / str / None 一律归一到两位小数（回调金额与订单金额比对建立在这一点上）。"""
    assert to_money(raw) == expect


def test_to_money_drops_float_binary_artifacts():
    """不得出现 float 二进制误差尾巴（如 8.800000000000001），
    否则回调金额与订单金额永远比对不上。"""
    assert str(to_money(8.8)) == "8.80"
    assert str(to_money(1.005)) == "1.00"          # float 1.005 实为 1.0049999…
    assert to_money(0.1 + 0.2) == Decimal("0.30")  # 0.30000000000000004 必须收回来


def test_to_money_keeps_distinct_amounts_distinct():
    """不同金额不得被换算成同一个值，否则金额校验形同虚设。"""
    values = [to_money(v) for v in (1.00, 1.01, 1.10, 10.0)]
    assert len(set(values)) == 4


def test_to_money_is_ordering_safe():
    """比较运算必须可直接用：对账差错判定依赖 < / > 的可用性。"""
    assert to_money("9.90") < to_money("10")
    assert to_money(-5) < to_money(5) < to_money("5.01")


def test_to_money_passes_decimal_through_unquantized():
    """已知口径：Decimal 入参原样返回、不再截两位。

    这意味着「三位小数会不会被抹平」取决于入参类型：
    to_money(39.904) == to_money(39.90) 为真，而 to_money(Decimal("39.904")) 保持 39.904。
    现在的调用点都安全——渠道回调的金额单位是「分」（整数），落库列是 Numeric(10,2)，
    两侧都不可能出现第三位小数。本用例把这一差异显式钉住：若将来有调用点把
    带第三位小数的 Decimal 传进来（例如按比例算出的佣金），必须改成显式 quantize，
    而不是指望 to_money 帮忙对齐。
    """
    assert to_money(Decimal("39.905")) == Decimal("39.905")
    assert to_money(Decimal("39.90")) == to_money("39.90")
    assert to_money(39.905) == to_money("39.90")
