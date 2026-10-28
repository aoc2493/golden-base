"""A3 每日渠道对账：账单解析、差错判定与台账幂等。

对账是资金链路的最后一道防线——回调会丢、主动查单会漏，只有逐笔轧账才能确定性发现
「渠道收了钱本地没单」「渠道已收款本地没履约」「渠道退多了本地没回收」。
这里锁四件事：

1. 解析按列名取值且能识别账单自身的结构（微信汇总表头、支付宝合计行），
   渠道调整列顺序时不能静默错位；
2. 七类差错的判定方向正确，且**除 status_mismatch 外一律不碰本地账**——
   判错方向自动平账就是真实资金错误；
3. 台账按 diff_key 幂等：补跑/重对不得把同一差错记成两笔，否则运营无法分辨真假；
4. 单日异常不得带走其它账单日已发现的差错（差错是资损证据，越早落库越安全）。

渠道账单下载需要真实商户号与证书，本机没有也不该有，因此只在最外层（凭据判断、账单下载、
补偿履约入口）打桩，判定与写账逻辑全部走真实代码路径。
"""
import logging
from datetime import date, datetime, timedelta
from decimal import Decimal

import pytest
from sqlalchemy import delete, select

from app.config import settings
from app.core.models import Order, ReconciliationDiff, Refund
from app.core.services import reconcile as rec

TODAY = date.today()
BILL_DATE = (TODAY - timedelta(days=5)).strftime("%Y-%m-%d")     # 距今 ≥2 天，允许报 local_only
RECENT_DATE = (TODAY - timedelta(days=1)).strftime("%Y-%m-%d")   # 跨日入账宽限窗口内

_WX_HEADER = ("商户订单号,微信订单号,交易时间,交易类型,交易状态,付款银行,订单金额,"
              "应结订单金额,商户退款单号,微信退款单号,退款金额,退款状态")


def _wx_row(order_no="", trade_no="WX1", status="SUCCESS", amount="39.90", settle=None,
            refund_no="", wx_refund_no="", refund_amount="", refund_status=""):
    return ",".join([order_no, trade_no, "2026-01-01 10:00:00", "JSAPI", status, "OTHER",
                     amount, settle if settle is not None else amount,
                     refund_no, wx_refund_no, refund_amount, refund_status])


def _wx_bill(*rows, header=_WX_HEADER, summary=True):
    text = header + "\n" + "\n".join(rows)
    if summary:
        # 真实账单在明细后是「汇总表头行 + 汇总数值行」两行，数值行首列是单数不是单号
        text += ("\n`总交易单数,`应结订单总金额,`退款总金额,`充值券退款金额,`订单总金额"
                 "\n`2,`80.00,`0.00,`0.00,`80.00")
    return text


def _day_time(bill_date, hour=10):
    return datetime.strptime(bill_date, "%Y-%m-%d") + timedelta(hours=hour)


def _order(bill_date=BILL_DATE, order_no="BZ0001", amount="39.90", status="completed",
           channel="wechat", paid=True, **kw):
    kw.setdefault("user_id", 1)
    kw.setdefault("product_name", "会员月卡")
    kw.setdefault("pay_channel", channel)
    kw.setdefault("pay_trade_no", "WX" + order_no[-6:])
    if "paid_at" not in kw:
        kw["paid_at"] = _day_time(bill_date) if paid else None
    return Order(id=kw.pop("id", None), order_no=order_no, amount=Decimal(amount),
                 status=status, **kw)


async def _rows(db, bill_date=None, channel="wechat"):
    stmt = select(ReconciliationDiff)
    if bill_date is not None:
        stmt = stmt.where(ReconciliationDiff.bill_date == bill_date)
    if channel is not None:
        stmt = stmt.where(ReconciliationDiff.channel == channel)
    return (await db.execute(stmt.order_by(ReconciliationDiff.diff_key))).scalars().all()


async def _types(db, bill_date=BILL_DATE, channel="wechat"):
    return [(r.diff_type, r.order_no) for r in await _rows(db, bill_date, channel)]


# ==================== 一、金额取值口径 ====================

@pytest.mark.parametrize("raw,expect", [
    ("39.90", Decimal("39.90")),
    ("`100.00", Decimal("100.00")),        # 微信字段带反引号前缀
    ("1,234.50", Decimal("1234.50")),      # 千分位
    (" 8.8 ", Decimal("8.80")),
    ("3.999", Decimal("4.00")),            # 统一量化到分，比对才不会因位数不同而误报
    ("", None), ("-", None), ("abc", None), (None, None),
])
def test_dec_never_guesses_zero(raw, expect):
    """缺失/非法金额必须是 None，不能猜成 0。

    把「账单里这一格是空的」当成 0 元，会凭空造出一批假 amount_mismatch，
    真差错被淹没在噪音里——对账报告一旦不可信，运营就不再看了，那才是最大的风险。
    """
    assert rec._dec(raw) == expect


def test_first_dec_keeps_a_real_zero():
    """首选列真的是 0 元时不得跳到备选列。

    `_dec(a) or _dec(b)` 这种写法会让 Decimal('0.00') 被当成假值跳过，
    恰好把最该暴露的 0 元入账（渠道异常/全额抵扣）抹平成一次「看起来正常」的比对。
    """
    assert rec._first_dec("0.00", "99.00") == Decimal("0.00")
    assert rec._first_dec("", "99.00") == Decimal("99.00")
    assert rec._first_dec(None, "-") is None


# ==================== 二、微信账单解析 ====================

def test_wechat_bill_splits_payments_and_refunds():
    text = _wx_bill(_wx_row("BZPAY1"),
                    _wx_row("BZREF1", refund_no="RFNO1", wx_refund_no="500001",
                            refund_amount="39.90", refund_status="SUCCESS"))
    payments, refunds = rec.parse_wechat_bill(text)
    assert [p["out_trade_no"] for p in payments] == ["BZPAY1"], "退款行混进了支付行"
    assert [r["out_refund_no"] for r in refunds] == ["RFNO1"]
    assert refunds[0]["amount"] == Decimal("39.90")
    assert refunds[0]["out_trade_no"] == "BZREF1"


def test_wechat_bill_stops_at_summary_header():
    """汇总表头之后的行不是明细：把「`2`」这种汇总数字当成订单号会造出假 channel_only。

    这里必须连汇总数值行一起断言，否则「break」被换成「跳过这一行」也测不出来——
    汇总表头是明细的最后边界，它后面的数值行同样会被当成一笔交易。
    """
    text = (_WX_HEADER + "\n" + _wx_row("BZPAY1")
            + "\n`总交易单数,`应结订单总金额,`退款总金额\n`1,`39.90,`0.00")
    payments, refunds = rec.parse_wechat_bill(text)
    assert [p["out_trade_no"] for p in payments] == ["BZPAY1"]
    assert refunds == []


def test_wechat_bill_uses_order_amount_not_settled():
    """必须取「订单金额」（用户应付总额，与本地 order.amount 同口径）。

    「应结订单金额」已扣商户代金券/优惠，拿它和本地订单金额比会把优惠差额误报成
    amount_mismatch——渠道口径一变动，对账报告就会天天报假错。
    """
    text = _wx_bill(_wx_row("BZPAY1", amount="100.00", settle="90.00"))
    payments, _ = rec.parse_wechat_bill(text)
    assert payments[0]["amount"] == Decimal("100.00")


def test_wechat_bill_falls_back_when_order_amount_empty():
    text = _wx_bill(_wx_row("BZPAY1", amount="", settle="90.00"))
    payments, _ = rec.parse_wechat_bill(text)
    assert payments[0]["amount"] == Decimal("90.00")


def test_wechat_bill_is_column_name_driven():
    """列顺序被渠道调整后仍按列名取值——硬编码下标会在某次升级后静默错位。"""
    shuffled = "交易状态,订单金额,商户退款单号,商户订单号,微信订单号,应结订单金额"
    row = "SUCCESS,39.90,,BZPAY1,WX9,39.90"
    payments, refunds = rec.parse_wechat_bill(shuffled + "\n" + row)
    assert payments[0]["out_trade_no"] == "BZPAY1"
    assert payments[0]["amount"] == Decimal("39.90")
    assert payments[0]["status"] == "SUCCESS"
    assert refunds == []


@pytest.mark.parametrize("text", ["", None, "\n\n", "商户订单号,微信订单号\n"])
def test_wechat_bill_degrades_on_junk(text):
    """空账单/只有表头：返回两个空列表而不是抛异常（对账任务不能因一天的坏文件整体失败）。"""
    assert rec.parse_wechat_bill(text) == ([], [])


# ==================== 三、支付宝账单解析 ====================

_ALI_PRELUDE = "#支付宝业务明细查询,对账单下载时间##"
_ALI_HEADER = ("交易号,商户订单号,业务类型,完成时间,发生时间,金额,退款批次号/请求号,支付宝交易号,"
               "商品名称,订单金额（元）,买家账号,店铺编号,账号来源,业务标识,收/支,收入金额（元）,"
               "支出金额（元）,交易状态,备注")


def _ali_row(trade_no="ALI1", order_no="BZPAY1", biz="纸质发票", paid_time="2026-01-01 10:00:00",
             amount="39.90", refund_req="", ali_trade="202600001", order_amount=None):
    cols = [trade_no, order_no, biz, paid_time, paid_time, amount, refund_req, ali_trade,
            "测试商品", order_amount if order_amount is not None else amount,
            "u@e.com", "s1", "a", "b", "收", amount, "0.00", "TRADE_SUCCESS", ""]
    return ",".join(cols)


def test_alipay_bill_locates_header_after_prelude():
    """前几行是标题/查询条件：表头必须靠「同时含支付宝交易号与商户订单号」定位。"""
    text = _ALI_PRELUDE + "\n" + _ALI_HEADER + "\n" + _ali_row()
    payments, refunds = rec.parse_alipay_bill(text)
    assert [p["out_trade_no"] for p in payments] == ["BZPAY1"]
    assert payments[0]["trade_no"] == "202600001"
    assert refunds == []


def test_alipay_bill_classifies_refund_rows():
    refund_row = _ali_row(order_no="BZREF1", biz="交易退款", refund_req="RFNO-ALI-1",
                          amount="39.90")
    text = _ALI_PRELUDE + "\n" + _ALI_HEADER + "\n" + _ali_row() + "\n" + refund_row
    payments, refunds = rec.parse_alipay_bill(text)
    assert [p["out_trade_no"] for p in payments] == ["BZPAY1"]
    assert [r["out_refund_no"] for r in refunds] == ["RFNO-ALI-1"]


def test_alipay_bill_stops_at_total_row():
    """末尾合计行不能被当成一笔交易（否则凭空多一条 channel_only）。"""
    text = (_ALI_PRELUDE + "\n" + _ALI_HEADER + "\n" + _ali_row() +
            "\n合计,,,,,,,,39.90,,,,,,39.90,,,,,")
    payments, _ = rec.parse_alipay_bill(text)
    assert len(payments) == 1


def test_alipay_bill_without_header_is_skipped(caplog):
    with caplog.at_level(logging.WARNING):
        assert rec.parse_alipay_bill("乱七八糟的一行\n另一行") == ([], [])
    assert "未识别到表头" in caplog.text


# ==================== 四、差错台账幂等 ====================

async def test_same_diff_recorded_once(db):
    """同一账单日重跑（补跑漏账、人工重对）不得产生第二条。"""
    kw = dict(bill_date=BILL_DATE, channel="wechat", diff_type="channel_only", order_no="BZ1")
    assert await rec._record_diff(db, **kw) is True
    assert await rec._record_diff(db, **kw) is False
    assert await _types(db) == [("channel_only", "BZ1")]


async def test_different_type_or_date_are_separate_rows(db):
    """幂等键含差错类型与账单日：同一订单的两种差错、同一差错的两天都必须各自留痕。"""
    base = dict(channel="wechat", diff_type="channel_only", order_no="BZ1")
    await rec._record_diff(db, bill_date=BILL_DATE, **base)
    await rec._record_diff(db, bill_date=BILL_DATE, channel="wechat",
                           diff_type="amount_mismatch", order_no="BZ1")
    await rec._record_diff(db, bill_date=RECENT_DATE, **base)
    assert len(await _rows(db, BILL_DATE, "wechat")) == 2
    assert len(await _rows(db, RECENT_DATE, "wechat")) == 1


async def test_severe_diff_logs_error_others_warning(db, caplog):
    """严重差错必须 ERROR 级（监控按级别采集告警），local_only 这类噪音用 WARNING。"""
    with caplog.at_level(logging.WARNING):
        await rec._record_diff(db, bill_date=BILL_DATE, channel="wechat",
                               diff_type="channel_only", order_no="BZ1")
        await rec._record_diff(db, bill_date=BILL_DATE, channel="wechat",
                               diff_type="local_only", order_no="BZ2")
    lines = [r.levelname for r in caplog.records if "对账差错" in r.getMessage()]
    assert lines == ["ERROR", "WARNING"], f"告警级别错配: {lines}"


async def test_row_already_in_the_ledger_is_recognised(db):
    """先查后插：台账里已有同 key 的行（补跑/人工重对）即识别为已存在，不产生第二条。

    边界说明（为什么这里只测到这一层）：`_record_diff` 里 `except IntegrityError` + SAVEPOINT
    兜的是「另一条连接在我们的 SELECT 之后提交了同 key 行」——那是定时任务与后台手动补跑
    重叠、或多 worker 并发时的跨进程时序。SQLite（本机的单事务内存库与轻量文件库）在写入前
    会先拿到锁，冲突表现为 database is locked 而不是唯一键冲突，因此这条分支只能在 MySQL 上
    真实触发；本机可复现的重复形态就是上面这种「已落库的同 key 行」，它由先查后插挡掉，
    也正是补跑/重对的日常路径。
    """
    await rec._record_diff(db, bill_date=BILL_DATE, channel="wechat",
                           diff_type="channel_only", order_no="BZKEEP")
    dup = ReconciliationDiff(diff_key=f"{BILL_DATE}|wechat|amount_mismatch|BZ2",
                             bill_date=BILL_DATE, channel="wechat",
                             diff_type="amount_mismatch", order_no="BZ2")
    db.add(dup)
    await db.flush()
    db.expire_all()
    ok = await rec._record_diff(db, bill_date=BILL_DATE, channel="wechat",
                                diff_type="amount_mismatch", order_no="BZ2")
    assert ok is False, "重复行应被识别为已存在"
    assert {d.diff_type for d in await _rows(db, BILL_DATE, "wechat")} == {
        "channel_only", "amount_mismatch"}
    # 台账里同 key 仍只有一条（先查后插没有先写再撞、也没留下半成品）
    assert len(await _rows(db, BILL_DATE, "wechat")) == 2


# ==================== 五、整日轧账的判定方向 ====================

def _stub(monkeypatch, bill, *, channel="wechat"):
    """只对「渠道是否配置」「账单内容」打桩，其余全走真实逻辑。

    bill 为 None 表示渠道账单拉取失败（与 download_channel_bill 的失败返回值一致）。
    """
    monkeypatch.setattr(rec, "_channel_configured", lambda got: got == channel)

    async def fake_download(bill_date, got_channel):
        return bill if got_channel == channel else None

    monkeypatch.setattr(rec, "download_channel_bill", fake_download)


def _stub_sync(monkeypatch, action="fulfilled", *, raises=False):
    calls = []

    async def fake_sync(session, order, source=None, background_tasks=None):
        calls.append({"order_no": order.order_no, "status": order.status, "source": source})
        if raises:
            raise RuntimeError("查单接口超时")
        return {"action": action}

    monkeypatch.setattr(rec, "sync_one_order", fake_sync)
    return calls


async def test_channel_only_is_recorded_without_touching_local_accounts(db, monkeypatch):
    """渠道收了钱、本地无此单：只留痕并带上渠道侧证据，绝不猜测归属。"""
    db.add(_order(order_no="BZLOCAL", status="completed"))
    await db.flush()
    _stub(monkeypatch, _wx_bill(_wx_row("BZLOCAL", amount="39.90"),
                                _wx_row("BZGHOST", amount="66.00", status="SUCCESS")))
    calls = _stub_sync(monkeypatch)

    summary = await rec.reconcile_day(db, BILL_DATE)
    assert set(summary["channels"]) == {"wechat"}, "未配置凭据的渠道不该进入对账"
    assert summary["diffs"] == 1
    rows = await _rows(db, BILL_DATE, "wechat")
    assert [(r.diff_type, r.order_no) for r in rows] == [("channel_only", "BZGHOST")]
    assert rows[0].channel_amount == Decimal("66.00")
    assert rows[0].channel_status == "SUCCESS", "没有渠道状态就无法判断资金归属"
    assert "须人工核查" in rows[0].detail
    assert calls == [], "本地无单却调用补偿入口 = 凭空造账"


async def test_amount_mismatch_never_compensates(db, monkeypatch):
    """金额不符时禁止自动履约——哪怕订单还停在 pending。

    这是判据里最关键的一条：金额不符意味着报文可能被篡改或渠道侧异常，
    此时按渠道金额补履约等于给一笔来路不明的钱发货，是真实资损。
    """
    db.add(_order(order_no="BZTAMPER", amount="99.00", status="pending"))
    await db.flush()
    _stub(monkeypatch, _wx_bill(_wx_row("BZTAMPER", amount="39.90")))
    calls = _stub_sync(monkeypatch)

    summary = await rec.reconcile_day(db, BILL_DATE)
    assert await _types(db) == [("amount_mismatch", "BZTAMPER")]
    assert summary["channels"]["wechat"]["compensated"] == 0
    assert calls == [], "金额不符必须拒绝自动履约"
    row = (await _rows(db, BILL_DATE, "wechat"))[0]
    assert (row.channel_amount, row.local_amount) == (Decimal("39.90"), Decimal("99.00"))
    assert row.local_status == "pending"
    assert "禁止自动履约" in row.detail


async def test_matched_completed_order_produces_no_diff(db, monkeypatch):
    """正例基线：渠道与本地完全一致的账单必须零差错，否则整条判定链恒报噪音也无从发现。"""
    db.add(_order(order_no="BZOK", status="completed"))
    await db.flush()
    _stub(monkeypatch, _wx_bill(_wx_row("BZOK", amount="39.90")))
    summary = await rec.reconcile_day(db, BILL_DATE)
    assert summary["diffs"] == 0
    assert summary["channels"]["wechat"] == {"payments": 1, "refunds": 0, "diffs": 0,
                                             "compensated": 0}
    assert await _rows(db, BILL_DATE, "wechat") == []


@pytest.mark.parametrize("order_status,sync_action,expect_call,expect_detail", [
    ("pending", "fulfilled", True, "已按回调同源入口自动补履约"),
    ("expired", "noop", True, "自动补偿未成功"),
    ("cancelled", "fulfilled", False, "自动补偿未成功"),
])
async def test_dropped_order_status_mismatch_is_always_recorded(
        db, monkeypatch, order_status, sync_action, expect_call, expect_detail):
    """掉单：补偿成功也要留痕，因为它证明回调链路丢过通知。

    只对 pending/expired 主动补履约；cancelled 是用户/后台明确关掉的单，
    对账没有权限把它复活——那是判错方向的改账。
    """
    db.add(_order(order_no="BZDROP", status=order_status))
    await db.flush()
    _stub(monkeypatch, _wx_bill(_wx_row("BZDROP", amount="39.90")))
    calls = _stub_sync(monkeypatch, action=sync_action)

    summary = await rec.reconcile_day(db, BILL_DATE)
    rows = await _rows(db, BILL_DATE, "wechat")
    assert [(r.diff_type, r.local_status) for r in rows] == [
        ("status_mismatch", order_status)]
    assert expect_detail in rows[0].detail
    assert len(calls) == (1 if expect_call else 0), f"补偿入口调用次数错: {calls}"
    if expect_call:
        assert calls[0]["source"] == f"reconcile:{BILL_DATE}", "留痕要能回溯到对账来源"
    assert summary["channels"]["wechat"]["compensated"] == (
        1 if (expect_call and sync_action == "fulfilled") else 0)


async def test_compensation_failure_still_records_and_does_not_abort(db, monkeypatch):
    """补偿入口抛异常（查单超时）不能中断整日轧账，且差错照常落账。"""
    db.add(_order(order_no="BZERR", status="pending"))
    await db.flush()
    _stub(monkeypatch, _wx_bill(_wx_row("BZERR", amount="39.90"), _wx_row("BZGHOST")))
    _stub_sync(monkeypatch, raises=True)

    summary = await rec.reconcile_day(db, BILL_DATE)
    assert sorted(t for t, _ in await _types(db)) == ["channel_only", "status_mismatch"], \
        "一条单的补偿异常不该吃掉同一天其它差错的判定"
    assert summary["diffs"] == 2


async def test_local_only_respects_the_two_day_grace(db, monkeypatch):
    """渠道跨日入账（23:59 支付、次日 00:01 入账单）很常见：宽限窗口内不报 local_only。

    每天都报一批假漏账会淹没真问题；靠回溯重跑收敛比当场误报有用。
    """
    for day, expect in ((RECENT_DATE, 0), (BILL_DATE, 1)):
        db.add(_order(order_no=f"BZLATE{expect}", status="completed", bill_date=day,
                      paid_at=_day_time(day, hour=23)))
    await db.flush()
    _stub(monkeypatch, _wx_bill())     # 账单可用但里面没有这两笔

    assert (await rec.reconcile_day(db, RECENT_DATE))["diffs"] == 0, "宽限窗口内误报"
    summary = await rec.reconcile_day(db, BILL_DATE)
    assert summary["diffs"] == 1
    assert await _types(db, BILL_DATE, "wechat") == [("local_only", "BZLATE1")]


async def test_bill_unavailable_is_a_diff_only_when_local_has_trades(db, monkeypatch):
    """账单拉不到：当天本地有交易＝对账链路故障（必须告警）；没交易＝当天无流水（不噪音）。"""
    _stub(monkeypatch, None)
    db.add(_order(order_no="BZNOSUPPORT", status="completed"))
    await db.flush()

    assert (await rec.reconcile_day(db, BILL_DATE))["diffs"] == 1
    rows = await _rows(db, BILL_DATE, "wechat")
    assert [r.diff_type for r in rows] == ["bill_unavailable"]
    assert "对账未完成" in rows[0].detail
    await db.execute(delete(ReconciliationDiff))
    await db.commit()

    empty_day = (TODAY - timedelta(days=4)).strftime("%Y-%m-%d")
    assert (await rec.reconcile_day(db, empty_day))["diffs"] == 0
    assert await _rows(db, empty_day, "wechat") == []


async def test_refund_direction_detects_both_missing_and_stale(db, monkeypatch):
    """渠道已退款而本地没回收＝用户白嫖。缺退款单、退款单未置成功都要抓到。"""
    db.add(_order(order_no="BZR1", status="refunded"))
    db.add(_order(order_no="BZR2", status="completed"))
    db.add(Refund(id=11, order_id=2, user_id=1, refund_no="RFLOCAL",
                  reason="用户申请", status="pending_refund"))
    await db.flush()
    _stub(monkeypatch, _wx_bill(
        # 微信 bill_type=ALL 的真实形态：同一笔单在账单里既有支付行也有退款行
        _wx_row("BZR1"), _wx_row("BZR2"),
        _wx_row("BZR1", refund_no="RFMISSING", wx_refund_no="500002", refund_amount="39.90",
                refund_status="SUCCESS"),
        _wx_row("BZR2", refund_no="RFLOCAL", wx_refund_no="500003", refund_amount="39.90",
                refund_status="SUCCESS")))

    summary = await rec.reconcile_day(db, BILL_DATE)
    rows = await _rows(db, BILL_DATE, "wechat")
    assert [r.diff_type for r in rows] == ["refund_local_missing", "refund_local_missing"]
    assert {(r.order_no, r.local_status) for r in rows} == {
        ("BZR1", None), ("BZR2", "pending_refund")}
    assert "权益可能未回收" in rows[0].detail
    assert "权益/佣金可能未回收" in rows[1].detail
    assert summary["diffs"] == 2


async def test_refund_over_paid_is_detected_even_when_local_refunds_are_complete(
        db, monkeypatch):
    """退款金额上限核对（只核状态不核金额会放过「本地记了退款、渠道退多了」）。

    本地 refunds 表没有金额列，所以只能在渠道账单侧按订单聚合退款额与订单实付额比上限。
    """
    db.add(_order(order_no="BZOVER", amount="39.90", status="refunded"))
    db.add(Refund(id=21, order_id=1, user_id=1, refund_no="RF1", reason="首次退款",
                  status="refunded"))
    db.add(Refund(id=22, order_id=1, user_id=1, refund_no="RF2", reason="二次退款",
                  status="refunded"))
    await db.flush()
    _stub(monkeypatch, _wx_bill(
        _wx_row("BZOVER"),
        _wx_row("BZOVER", refund_no="RF1", refund_amount="25.00", refund_status="SUCCESS"),
        _wx_row("BZOVER", refund_no="RF2", refund_amount="20.00", refund_status="SUCCESS")))

    await rec.reconcile_day(db, BILL_DATE)
    rows = await _rows(db, BILL_DATE, "wechat")
    assert [r.diff_type for r in rows] == ["refund_over_paid"], \
        "渠道累计退款 45.00 超过实付 39.90 必须报出，且不因本地退款单齐全而静默"
    assert rows[0].channel_amount == Decimal("45.00")
    assert rows[0].local_amount == Decimal("39.90")


async def test_refund_exactly_at_paid_amount_is_not_over_paid(db, monkeypatch):
    """等于实付额不算多退：把边界判成差错会让每笔正常全额退款都报警。"""
    db.add(_order(order_no="BZFULL", amount="39.90", status="refunded"))
    db.add(Refund(id=31, order_id=1, user_id=1, refund_no="RF1", reason="全额退款",
                  status="refunded"))
    await db.flush()
    _stub(monkeypatch, _wx_bill(
        _wx_row("BZFULL"),
        _wx_row("BZFULL", refund_no="RF1", refund_amount="39.90", refund_status="SUCCESS")))
    assert (await rec.reconcile_day(db, BILL_DATE))["diffs"] == 0


async def test_refund_without_local_order_is_not_double_counted(db, monkeypatch):
    """渠道退款但本地连订单都没有：归 channel_only/refund_local_missing 处理，
    不再重复报 refund_over_paid（同一件事报两条会让运营以为有两笔损失）。"""
    _stub(monkeypatch, _wx_bill(
        _wx_row("BZGHOST", refund_no="RF1", refund_amount="99.00", refund_status="SUCCESS")))
    await rec.reconcile_day(db, BILL_DATE)
    assert [r.diff_type for r in await _rows(db, BILL_DATE, "wechat")] == [
        "refund_local_missing"]


async def test_reconcile_never_mutates_order_or_refund_status(db, monkeypatch):
    """「只发现、只留痕、不自动改账」是这条链路的处置口径，必须钉死。

    本地补偿只经由回调同源入口（其内部会重新实时查单并校验金额），对账自身不得改任何账：
    判错方向就是多发货或少退款。这里断言补偿之外所有差错的账目都不动。
    """
    db.add(_order(order_no="BZM1", amount="99.00", status="pending"))      # amount_mismatch
    db.add(_order(order_no="BZM2", status="completed", paid_at=_day_time(BILL_DATE, 23)))  # local_only
    db.add(Refund(id=41, order_id=2, user_id=1, refund_no="RFX", reason="待确认",
                  status="pending_refund"))
    await db.flush()
    _stub(monkeypatch, _wx_bill(
        _wx_row("BZM1", amount="39.90"),
        _wx_row("BZGHOST", amount="10.00"),
        _wx_row("BZM2", refund_no="RFX", refund_amount="39.90", refund_status="SUCCESS")))
    calls = _stub_sync(monkeypatch)

    summary = await rec.reconcile_day(db, BILL_DATE)
    assert summary["diffs"] == 4, sorted(await _types(db))
    assert calls == [], "四类差错都不该触发补偿履约"
    orders = {o.order_no: o for o in (await db.execute(select(Order))).scalars().all()}
    assert orders["BZM1"].status == "pending"
    assert orders["BZM2"].status == "completed"
    refund = (await db.execute(select(Refund))).scalars().first()
    assert refund.status == "pending_refund", "渠道已退款不等于本地可以替它置成功"


# ==================== 六、回溯窗口 ====================

async def test_reconcile_recent_skips_when_disabled(monkeypatch):
    monkeypatch.setattr(settings, "RECONCILE_ENABLED", False)
    assert await rec.reconcile_recent(None) == {"skipped": True}   # db 都不会被用到


async def test_reconcile_recent_covers_lookback_window_but_not_today(db, monkeypatch):
    """回溯窗口必须含「今天之前」的每一天、且绝不包含今天：当天账单尚未生成，
    微信次日 09:00 才出账，拉今天的单必然失败并制造一批 bill_unavailable 噪音。"""
    seen = []

    async def fake_download(bill_date, channel):
        seen.append(bill_date)
        return _wx_bill()

    monkeypatch.setattr(rec, "_channel_configured", lambda channel: channel == "wechat")
    monkeypatch.setattr(rec, "download_channel_bill", fake_download)
    result = await rec.reconcile_recent(db)
    assert len(result["days"]) == settings.RECONCILE_LOOKBACK_DAYS
    assert seen == [(TODAY - timedelta(days=i)).strftime("%Y-%m-%d")
                    for i in range(settings.RECONCILE_LOOKBACK_DAYS, 0, -1)]
    assert TODAY.strftime("%Y-%m-%d") not in seen
    assert result["total_diffs"] == 0


async def test_one_bad_day_does_not_lose_another_days_diffs(db, monkeypatch):
    """单日异常（账单接口报错）不得把另一天已发现的差错一起回滚掉。

    逐日提交的意义正在这里：差错是资损证据，越早落库越安全；
    而且异常若发生在 SQL 执行中，session 会停在 pending-rollback，
    不显式回滚就会让后续每一天连锁失败，一次抖动废掉整个回溯窗口。
    """
    bad_day = (TODAY - timedelta(days=2)).strftime("%Y-%m-%d")

    async def fake_download(bill_date, channel):
        if bill_date == bad_day:
            raise RuntimeError("账单下载 500")
        return _wx_bill(_wx_row("BZGHOST", amount="10.00"))

    monkeypatch.setattr(rec, "_channel_configured", lambda c: c == "wechat")
    monkeypatch.setattr(rec, "download_channel_bill", fake_download)

    result = await rec.reconcile_recent(db)
    errors = [d for d in result["days"] if "error" in d]
    assert [e["bill_date"] for e in errors] == [bad_day]
    assert "账单下载 500" in errors[0]["error"]
    good_days = [d["bill_date"] for d in result["days"] if "error" not in d]
    assert len(good_days) == settings.RECONCILE_LOOKBACK_DAYS - 1
    persisted = await _rows(db, channel="wechat")
    assert {r.bill_date for r in persisted} == set(good_days), \
        "坏掉的一天不该带走其它天已落账的差错"
    assert all(r.diff_type == "channel_only" for r in persisted)


async def test_reconcile_recent_aggregates_and_alerts(db, monkeypatch, caplog):
    """回溯结束要有汇总：差错总数只有一条 ERROR 级告警，监控才能按级别抓到。"""
    async def fake_download(bill_date, channel):
        return _wx_bill(_wx_row("BZGHOST", amount="10.00"))

    monkeypatch.setattr(rec, "_channel_configured", lambda c: c == "wechat")
    monkeypatch.setattr(rec, "download_channel_bill", fake_download)
    with caplog.at_level(logging.WARNING):
        result = await rec.reconcile_recent(db)
    assert result["total_diffs"] == settings.RECONCILE_LOOKBACK_DAYS
    assert any("对账告警" in r.getMessage() and r.levelname == "ERROR" for r in caplog.records)
