"""周岁推算与年龄门槛的接线状态。

年龄门槛（付款人成年 / 不满十四周岁须监护人同意 / 采集他人出生信息的合法性基础）在本底座
里整段关闭，`gate_payer`、`gate_bio` 恒放行。这个状态本身是产品决定，
不在本文件的断言范围里；本文件锁的是**重新打开时会用到的判据**——周岁推算。

为什么判据必须有测试：门槛代码无人调用，就会长期零覆盖。等到重新接线那天，
「生日当天算满」「闰日出生的满龄日」「农历没换算插件时怎么办」这三条都是静默出错型
——结论偏一个月，恰好把 17 岁的人当 18 岁放行、或把成年人拦在门外，而线上没有任何信号。
公历判据与门槛开关无关（declare 写留痕时同样要用），所以照旧锁死。
"""
import logging
from datetime import date, datetime

import pytest

from app.core.services import minor_guard as guard


# ==================== 一、周岁推算（公历，判据本体） ====================

@pytest.mark.parametrize("birth,ref,expect", [
    ("2000-01-01", date(2018, 1, 1), 18),    # 生日当天即满（户籍口径）
    ("2000-01-01", date(2017, 12, 31), 17),  # 差一天就是未成年人
    ("2000-12-31", date(2018, 12, 31), 18),
    ("2000-12-31", date(2018, 12, 30), 17),
    ("2000-02-29", date(2018, 2, 28), 17),   # 闰日：非闰年 2/28 尚未满
    ("2000-02-29", date(2018, 3, 1), 18),    # 3/1 起算满
    ("2005-06-15", datetime(2023, 6, 15, 0, 0, 1), 18),  # 接受 datetime 参照
])
def test_age_of_boundary_days(birth, ref, expect):
    """门槛就卡在生日前后一天，所以只测「差一天」才有意义。"""
    assert guard.age_of(birth, "solar", ref) == expect


@pytest.mark.parametrize("birth", [
    "", None, "2000", "2000-01", "2000-01-01-01",
    "2000-02-31",     # 形如日期但不是真实日期：过得了正则，构造不出 date
    "2000-13-01",
    "abc-def-ghi",
])
def test_age_of_returns_none_for_unparsable(birth):
    """无法推算一律返回 None，绝不返回 0 或猜一个年龄。

    0 会被「未成年」分支当成事实，猜大则直接放过未成年人充值——两种都比 None 糟。
    """
    assert guard.age_of(birth, "solar", date(2024, 1, 1)) is None


def test_age_of_rejects_out_of_range():
    """早于 MIN_BIRTH_YEAR 与晚于参照日都算推算失败。

    1899 年这种明显误填若能算出 120 岁，成年校验就形同虚设；未来出生日期同理，
    负数周岁不能参与比较。
    """
    assert guard.MIN_BIRTH_YEAR == 1900
    assert guard.age_of("1899-12-31", "solar", date(2024, 1, 1)) is None
    assert guard.age_of("2099-01-01", "solar", date(2024, 1, 1)) is None


def test_legal_thresholds_are_constants_not_settings():
    """18/14 两个法定门槛必须是常量。

    做成 .env 开关就等于允许一次配置改动静默关掉未成年人保护且不留痕——
    比根本没有这项保护更难向监管解释。
    """
    assert (guard.ADULT_AGE, guard.CHILD_AGE) == (18, 14)


# ==================== 二、农历入参 ====================

def test_lunar_without_converter_falls_back_and_warns(caplog):
    """没有任何插件提供农历换算时：退回按公历推算，并留 WARNING。

    开源骨架里的 demo 插件就是 `lunar_converter()` 返回 None，所以这条路径是
    使用者最先会撞上的：退回口径保证「农历生日」不会被算成「无法推算」而静默失效，
    而留痕让运维能看出换算其实没生效（最大偏差一个月）。
    """
    from app.plugins import registry

    assert registry.lunar_converter() is None, "前提：当前没有任何插件提供农历换算"
    with caplog.at_level(logging.WARNING):
        solar = guard.solar_of("2000-01-01", "lunar")
    assert solar == date(2000, 1, 1), f"应退回按公历解读，实际 {solar}"
    assert "农历" in caplog.text, "换算不可用必须留 WARNING，否则是静默降级"


def test_lunar_uses_plugin_converter_when_available(monkeypatch):
    """插件提供换算时按换算结果推算——农历正月初一落在公历 1~2 月之间，
    不换算就直接差出一个多月，跨 14/18 岁生日时结论会反。

    这里用临时插件位注入换算器（core 只能通过 registry 钩子拿到换算，不 import 具体插件），
    用例结束由 fixture 自动注销，不污染其它用例的插件视图。
    """
    from app.core.plugin_contract import PluginManifest
    from app.plugins import PluginEntry, registry

    class _LunarService:
        def lunar_converter(self):
            # 假装农历 2000-正月初一 = 公历 2000-02-05（真实历法由插件负责，这里只验接线）
            return lambda y, m, d: date(2000, 2, 5) if (m, d) == (1, 1) else None

    entry = PluginEntry(name="lunar-probe",
                        manifest=PluginManifest(name="lunar-probe", display_name="农历换算探针"),
                        service=_LunarService())
    registry.plugins["lunar-probe"] = entry
    guard._lunar_to_solar_cached.cache_clear()
    try:
        assert guard.solar_of("2000-01-01", "lunar") == date(2000, 2, 5)
        # 插件换算不出来的日子（返回 None）同样退回按公历
        assert guard.solar_of("2000-06-06", "lunar") == date(2000, 6, 6)
    finally:
        registry.plugins.pop("lunar-probe", None)
        guard._lunar_to_solar_cached.cache_clear()


def test_solar_input_is_never_converted():
    """calendar_type 只认 lunar，其它值（含空、大写、乱填）一律按公历原样解读。

    这条防止「前端传了 Lunar / LUNAR / 1 之类，后端当成农历去换算」的口径漂移。
    """
    for cal in ("solar", "SOLAR", "", None, "  ", "gregorian", "1"):
        assert guard.solar_of("2000-01-01", cal) == date(2000, 1, 1)


# ==================== 三、接线状态：门槛按本项目决策恒放行 ====================

def test_owner_decision_keeps_payer_gate_open():
    """锁住当前决定：未满 18 周岁的付款人也放行。

    这条不是在为放行背书，而是把「谁在什么时候改了这个决定」变成一次显式的代码改动：
    重新打开门槛时必须改这里，改不动就是因为测试在提醒你需要产品侧决策留痕。
    """
    minor = type("U", (), {"birth_date": "2010-01-01"})()
    assert guard.gate_payer(minor) is None


def test_modules_docstring_declares_no_callers():
    """模块顶部必须写明「三道门槛全部关闭」，而不是让读者以为它在拦。

    文档口径与实态不符本身就是风险：审查者按文档假设平台有未成年人保护，
    而实际一个请求都没拦。
    """
    doc = (guard.__doc__ or "")
    assert "三道门槛全部关闭" in doc
    assert "恒放行" in doc or "关闭" in doc
