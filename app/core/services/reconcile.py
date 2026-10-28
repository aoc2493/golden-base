"""A3：每日渠道对账（轧账）。

对账是资金系统的最后一道防线：回调会丢、主动查单也可能因窗口/批量限制漏掉，只有把渠道账单
与本地账逐笔比对，才能确定性发现这几类真实资损：
  · channel_only          渠道收了钱，本地根本没有这张单
  · status_mismatch       渠道已收款，本地订单仍停在 pending/expired（掉单，用户付了钱没开通）
  · amount_mismatch       渠道入账金额与订单金额不符（可能被篡改，或渠道侧异常）
  · refund_local_missing  渠道已退款，本地退款单缺失或未置成功（权益没回收 → 用户白嫖）
  · local_only            本地已完成，渠道账单里没有这笔（疑似漏账/跨日/串商户号）
  · bill_unavailable      本地当天有交易但账单拉不到（对账链路自身故障，必须告警）

处置口径：**只发现、只留痕，不自动改账**。差异成因横跨渠道跨日入账、退款回调丢失、金额篡改、
本地漏单、账单口径差异，自动平账一旦判错方向就是真实资金错误（多发货或少退款），风险远大于收益。
唯一例外是 status_mismatch：它意味着「渠道确已收款而本地未履约」，此时调用
payment_sync.sync_one_order 走与回调完全相同的 CAS 履约入口补发放——该入口会重新向渠道
实时查单并校验金额，因此补偿是安全的，且幂等（重复对账不会重复发放）。

差错以 diff_key 唯一约束幂等入库，同一账单日重跑（补跑漏账、人工重对）不产生重复行。
"""
import csv
import io
import logging
from datetime import date, datetime, timedelta
from decimal import Decimal, InvalidOperation

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.models import Order, ReconciliationDiff, Refund
from app.core.services.payment_sync import sync_one_order
from app.core.utils.payment import alipay, download_channel_bill, wechat_pay

logger = logging.getLogger(__name__)

# 需要立刻人工介入的严重差错（ERROR 级留痕，供监控采集告警）
_SEVERE = ("channel_only", "amount_mismatch", "refund_local_missing", "status_mismatch",
           "bill_unavailable")


def _dec(value) -> Decimal:
    """账单金额转 Decimal。空串/None/非法值一律 None，绝不猜成 0——
    把缺失金额当 0 参与比对会制造大量假 amount_mismatch。"""
    if value is None:
        return None
    s = str(value).strip().lstrip("`").replace(",", "")
    if not s:
        return None
    try:
        return Decimal(s).quantize(Decimal("0.01"))
    except InvalidOperation:
        return None


def _clean(field: str) -> str:
    """微信账单每个字段都带反引号前缀（防 Excel 把长数字转科学计数），统一去掉并 trim。"""
    return (field or "").strip().lstrip("`").strip()


def _first_dec(*values):
    """返回第一个能解析出金额的值，全部不可解析时返回 None。

    必须显式判 None 而不能写 `_dec(a) or _dec(b)`：Decimal('0.00') 是假值，
    一旦首选列真的为 0（全额代金券抵扣、渠道异常入账 0 元）就会跳到备选列，
    拿一个看似合理的金额去比对，恰好把最该暴露的 0 元差错抹平。"""
    for v in values:
        d = _dec(v)
        if d is not None:
            return d
    return None


def parse_wechat_bill(text: str) -> tuple:
    """解析微信交易账单（bill_type=ALL，UTF-8 CSV）→ (支付行列表, 退款行列表)。

    结构：表头行 → 明细行 → 汇总表头（以「总交易单数」开头）→ 汇总行。明细止于汇总表头。
    按列名取值而非固定下标：微信调整过列顺序，硬编码下标会在某次升级后静默错位。
    """
    payments, refunds = [], []
    if not text:
        return payments, refunds
    rows = list(csv.reader(io.StringIO(text)))
    if not rows:
        return payments, refunds
    header = [_clean(h) for h in rows[0]]
    idx = {name: i for i, name in enumerate(header)}

    def get(row, name):
        i = idx.get(name)
        return _clean(row[i]) if i is not None and i < len(row) else ""

    for row in rows[1:]:
        if not row or not any(x.strip() for x in row):
            continue
        first = row[0].strip()
        if first.startswith("总交易单数") or first.startswith("`总交易单数"):
            break                                    # 明细结束，后面是汇总
        out_trade_no = get(row, "商户订单号")
        if not out_trade_no:
            continue
        out_refund_no = get(row, "商户退款单号")
        if out_refund_no:
            refunds.append({
                "out_trade_no": out_trade_no,
                "out_refund_no": out_refund_no,
                "refund_id": get(row, "微信退款单号"),
                "amount": _dec(get(row, "退款金额")),
                "status": get(row, "退款状态"),
                "trade_time": get(row, "交易时间"),
            })
            continue
        payments.append({
            "out_trade_no": out_trade_no,
            "trade_no": get(row, "微信订单号"),
            # 取「订单金额」（用户应付总额，与本地 order.amount 同口径）而非「应结订单金额」：
            # 后者已扣除商户代金券/优惠，本项目不发放代金券时两者相等，但一旦不等，用应结金额
            # 比对会把「优惠造成的差额」误报成 amount_mismatch。应结列仅作缺列时的兜底。
            "amount": _first_dec(get(row, "订单金额"), get(row, "应结订单金额")),
            "status": get(row, "交易状态"),
            "trade_time": get(row, "交易时间"),
        })
    return payments, refunds


def parse_alipay_bill(text: str) -> tuple:
    """解析支付宝业务明细 CSV（GBK，已在 utils.payment._extract_bill_csv 解码）→ (支付行, 退款行)。

    支付宝账单前若干行可能是标题/查询条件，末尾可能有合计行，因此表头按「同时含
    支付宝交易号 与 商户订单号」定位，数据行遇到合计/分隔线即止。
    退款行的特征：业务类型含「退款」，或退款批次号/请求号非空（此时 out_trade_no 可能为空）。
    """
    payments, refunds = [], []
    if not text:
        return payments, refunds
    rows = list(csv.reader(io.StringIO(text)))
    header_at, header = None, []
    for i, row in enumerate(rows):
        joined = "".join(row)
        if "支付宝交易号" in joined and "商户订单号" in joined:
            header_at, header = i, [c.strip() for c in row]
            break
    if header_at is None:
        logger.warning("支付宝账单未识别到表头，跳过解析")
        return payments, refunds
    idx = {name: i for i, name in enumerate(header)}

    def get(row, *names):
        for name in names:
            i = idx.get(name)
            if i is not None and i < len(row):
                v = row[i].strip()
                if v:
                    return v
        return ""

    for row in rows[header_at + 1:]:
        if not row or not any(x.strip() for x in row):
            continue
        joined = "".join(row)
        if joined.startswith("#") or "合计" in joined or "总计" in joined or set(joined) <= {"-", "="}:
            break
        biz_type = get(row, "业务类型")
        refund_req = get(row, "退款批次号/请求号", "退款批次号", "请求号")
        out_trade_no = get(row, "商户订单号")
        amount = _dec(get(row, "订单金额（元）", "订单金额(元)", "订单金额"))
        if "退款" in biz_type or refund_req:
            refunds.append({
                "out_trade_no": out_trade_no,
                "out_refund_no": refund_req,
                "refund_id": get(row, "支付宝交易号"),
                "amount": amount,
                "status": biz_type or "REFUND",
                "trade_time": get(row, "完成时间", "创建时间"),
            })
            continue
        if not out_trade_no:
            continue
        payments.append({
            "out_trade_no": out_trade_no,
            "trade_no": get(row, "支付宝交易号"),
            "amount": amount,
            "status": biz_type or "TRADE_SUCCESS",
            "trade_time": get(row, "完成时间", "创建时间"),
        })
    return payments, refunds


async def _record_diff(db: AsyncSession, *, bill_date: str, channel: str, diff_type: str,
                       order_no=None, channel_trade_no=None, channel_amount=None,
                       local_amount=None, channel_status=None, local_status=None,
                       detail=None) -> bool:
    """幂等写入差错台账。返回 True 表示本次新增（False 表示此前已记录过）。

    先查后插挡不住两种重复：① 并发对账（定时任务与后台手动补跑重叠）；② 同一账单内
    同一单号产生两条同类差错（此时第二条的 select 看不到第一条尚未 flush 的 pending 行）。
    靠 diff_key 唯一约束兜底，并用 SAVEPOINT 把 INSERT 单独包起来：冲突只回滚这一条，
    不会让 IntegrityError 冒泡到整日提交、把当天已发现的其它差错一起丢掉
    （与插件在交付钩子里建 Report 行同一范式）。
    """
    diff_key = f"{bill_date}|{channel}|{diff_type}|{order_no or channel_trade_no or ''}"[:160]
    exists = (await db.execute(select(ReconciliationDiff.id).where(
        ReconciliationDiff.diff_key == diff_key))).first()
    if exists:
        return False
    db.add(ReconciliationDiff(
        diff_key=diff_key, bill_date=bill_date, channel=channel, diff_type=diff_type,
        order_no=order_no, channel_trade_no=channel_trade_no,
        channel_amount=channel_amount, local_amount=local_amount,
        channel_status=channel_status, local_status=local_status,
        detail=(detail or "")[:500]))
    try:
        async with db.begin_nested():
            await db.flush()
    except IntegrityError:
        logger.info(f"[对账差错] 已存在（并发或同日重复），跳过 diff_key={diff_key}")
        return False
    line = (f"[对账差错] {diff_type} date={bill_date} channel={channel} order={order_no} "
            f"channel_amount={channel_amount} local_amount={local_amount} "
            f"channel_status={channel_status} local_status={local_status} detail={detail}")
    if diff_type in _SEVERE:
        logger.error(line)
    else:
        logger.warning(line)
    return True


def _channel_configured(channel: str) -> bool:
    return wechat_pay.is_configured() if channel == "wechat" else alipay.is_configured()


async def reconcile_day(db: AsyncSession, bill_date: str) -> dict:
    """对单个账单日轧账。bill_date 格式 YYYY-MM-DD。返回各渠道统计。"""
    summary = {"bill_date": bill_date, "channels": {}, "diffs": 0}
    day_start = datetime.strptime(bill_date, "%Y-%m-%d")
    day_end = day_start + timedelta(days=1)
    # local_only 的宽限：渠道跨日入账很常见（23:59 支付、次日 00:01 入账单），
    # 距今不足 2 天的账单日不报 local_only，靠 RECONCILE_LOOKBACK_DAYS 的后续重跑收敛，
    # 否则每天都会产出一批假差错淹没真问题。
    allow_local_only = (date.today() - day_start.date()).days >= 2

    for channel in ("wechat", "alipay"):
        if not _channel_configured(channel):
            continue
        # 本地当天是否有该渠道的交易：账单拉不到时用于区分「当天没生意」与「对账链路故障」
        local_paid_count = (await db.execute(select(Order.id).where(
            Order.pay_channel == channel, Order.paid_at >= day_start,
            Order.paid_at < day_end).limit(1))).first()

        text = await download_channel_bill(bill_date, channel)
        if text is None:
            if local_paid_count:
                summary["diffs"] += 1 if await _record_diff(
                    db, bill_date=bill_date, channel=channel, diff_type="bill_unavailable",
                    detail="本地当天有已支付订单但渠道账单拉取失败，对账未完成，需人工下载核对"
                ) else 0
            else:
                logger.info(f"[对账] {bill_date} {channel} 无账单且本地无交易，视为当天无流水")
            continue

        payments, refunds = (parse_wechat_bill(text) if channel == "wechat"
                             else parse_alipay_bill(text))
        stat = {"payments": len(payments), "refunds": len(refunds), "diffs": 0,
                "compensated": 0}

        # ---- 方向一：渠道 → 本地（严重方向，必查）----
        order_nos = [p["out_trade_no"] for p in payments]
        local_orders = {}
        if order_nos:
            rows = (await db.execute(select(Order).where(
                Order.order_no.in_(order_nos)))).scalars().all()
            local_orders = {o.order_no: o for o in rows}

        for p in payments:
            order = local_orders.get(p["out_trade_no"])
            if order is None:
                stat["diffs"] += 1 if await _record_diff(
                    db, bill_date=bill_date, channel=channel, diff_type="channel_only",
                    order_no=p["out_trade_no"], channel_trade_no=p.get("trade_no"),
                    channel_amount=p.get("amount"), channel_status=p.get("status"),
                    detail="渠道已收款但本地无此订单：疑似串商户号或本地单缺失，须人工核查资金归属"
                ) else 0
                continue
            if p.get("amount") is not None and order.amount is not None:
                if Decimal(str(order.amount)).quantize(Decimal("0.01")) != p["amount"]:
                    stat["diffs"] += 1 if await _record_diff(
                        db, bill_date=bill_date, channel=channel, diff_type="amount_mismatch",
                        order_no=order.order_no, channel_trade_no=p.get("trade_no"),
                        channel_amount=p["amount"], local_amount=Decimal(str(order.amount)),
                        channel_status=p.get("status"), local_status=order.status,
                        detail="渠道入账金额与订单金额不符，禁止自动履约，须人工核查"
                    ) else 0
                    continue
            if order.status in ("completed", "refunded", "refund_pending"):
                continue
            # 渠道已收款而本地未履约（pending/expired/cancelled）= 掉单。
            # 先尝试用与回调同一入口补偿履约（内部会重新实时查单并校验金额，安全且幂等），
            # 再把差错记入台账留痕——即使补偿成功也要留记录，因为它证明回调链路丢过通知。
            compensated = False
            if order.status in ("pending", "expired"):
                try:
                    r = await sync_one_order(db, order, source=f"reconcile:{bill_date}")
                    compensated = r.get("action") == "fulfilled"
                except Exception as e:
                    logger.error(f"[对账] 补偿履约异常 order={order.order_no}: {e}")
            if compensated:
                stat["compensated"] += 1
            stat["diffs"] += 1 if await _record_diff(
                db, bill_date=bill_date, channel=channel, diff_type="status_mismatch",
                order_no=order.order_no, channel_trade_no=p.get("trade_no"),
                channel_amount=p.get("amount"), local_amount=Decimal(str(order.amount)),
                channel_status=p.get("status"), local_status=order.status,
                detail=("渠道已收款而本地未履约；已按回调同源入口自动补履约" if compensated
                        else "渠道已收款而本地未履约；自动补偿未成功（订单已取消或补偿失败），须人工处理")
            ) else 0

        # ---- 退款方向：渠道已退款而本地未回收（用户白嫖风险）----
        refund_nos = [r["out_refund_no"] for r in refunds if r.get("out_refund_no")]
        local_refunds = {}
        if refund_nos:
            rows = (await db.execute(select(Refund).where(
                Refund.refund_no.in_(refund_nos)))).scalars().all()
            local_refunds = {r.refund_no: r for r in rows}
        for rf in refunds:
            key = rf.get("out_refund_no")
            if not key:
                continue
            local_refund = local_refunds.get(key)
            if local_refund is None:
                stat["diffs"] += 1 if await _record_diff(
                    db, bill_date=bill_date, channel=channel, diff_type="refund_local_missing",
                    order_no=rf.get("out_trade_no"), channel_trade_no=rf.get("refund_id"),
                    channel_amount=rf.get("amount"), channel_status=rf.get("status"),
                    detail="渠道已退款但本地无对应退款单，权益可能未回收，须人工核查并冲回"
                ) else 0
                continue
            if local_refund.status != "refunded":
                stat["diffs"] += 1 if await _record_diff(
                    db, bill_date=bill_date, channel=channel, diff_type="refund_local_missing",
                    order_no=rf.get("out_trade_no"), channel_trade_no=rf.get("refund_id"),
                    channel_amount=rf.get("amount"), local_amount=None,
                    channel_status=rf.get("status"), local_status=local_refund.status,
                    detail=f"渠道退款已成功而本地退款单状态为 {local_refund.status}，"
                           f"权益/佣金可能未回收，须人工核查"
                ) else 0

        # ---- 退款金额核对（P2 修复）：渠道累计退款额不得超过订单实付额 ----
        # 本地 refunds 表无金额字段，故以订单维度聚合渠道账单退款额做上限核对；
        # 超出即「多退/串单/对账口径异常」，属于资损信号（原实现只核状态不核金额，
        # 「本地已记退款、渠道退多了」这类差错会被静默放过）。
        if refunds:
            _order_nos = {rf.get("out_trade_no") for rf in refunds if rf.get("out_trade_no")}
            _paid_map = {}
            if _order_nos:
                _rows = (await db.execute(select(Order).where(
                    Order.order_no.in_(_order_nos)))).scalars().all()
                _paid_map = {o.order_no: o for o in _rows}
            _agg = {}
            for rf in refunds:
                _no = rf.get("out_trade_no")
                if not _no:
                    continue
                try:
                    _agg[_no] = _agg.get(_no, Decimal("0")) + Decimal(str(rf.get("amount") or 0))
                except InvalidOperation:
                    pass
            for _no, _refunded_total in _agg.items():
                _o = _paid_map.get(_no)
                if _o is None:
                    continue  # 无本地订单的渠道退款已由上方 refund_local_missing 覆盖
                if _refunded_total > Decimal(str(_o.amount)):
                    stat["diffs"] += 1 if await _record_diff(
                        db, bill_date=bill_date, channel=channel, diff_type="refund_over_paid",
                        order_no=_no, channel_amount=_refunded_total,
                        local_amount=Decimal(str(_o.amount)),
                        detail="渠道累计退款额超过订单实付金额（多退/串单），须人工核查并追回"
                    ) else 0

        # ---- 方向二：本地 → 渠道（宽松，仅在账单日距今 ≥2 天时报）----
        if allow_local_only:
            paid_rows = (await db.execute(select(Order).where(
                Order.pay_channel == channel, Order.paid_at >= day_start, Order.paid_at < day_end,
                Order.status.in_(["completed", "refunded", "refund_pending"])))).scalars().all()
            channel_nos = {p["out_trade_no"] for p in payments}
            for o in paid_rows:
                if o.order_no in channel_nos:
                    continue
                stat["diffs"] += 1 if await _record_diff(
                    db, bill_date=bill_date, channel=channel, diff_type="local_only",
                    order_no=o.order_no, channel_trade_no=o.pay_trade_no,
                    local_amount=Decimal(str(o.amount)), local_status=o.status,
                    detail="本地已完成但渠道账单无此笔：可能跨日入账/账单口径差异/串商户号，请人工核对"
                ) else 0

        summary["channels"][channel] = stat
        summary["diffs"] += stat["diffs"]
    return summary


async def reconcile_recent(db: AsyncSession) -> dict:
    """回溯 RECONCILE_LOOKBACK_DAYS 天逐日对账（补跑漏账）。

    不含今天：当天账单尚未生成（微信次日 09:00 出账），拉取必然失败只会产生噪音。

    逐日提交而非全部跑完再提交：① 后一天报错不该把前一天已发现的差错一起回滚掉（差错是
    资损证据，越早落库越安全）；② 异常若发生在 SQL 执行中，session 会停在 pending-rollback，
    不回滚则后续每一天的查询都会连锁报 PendingRollbackError，一次抖动就让整个回溯窗口失效。
    """
    if not settings.RECONCILE_ENABLED:
        return {"skipped": True}
    results = []
    for i in range(settings.RECONCILE_LOOKBACK_DAYS, 0, -1):
        bill_date = (date.today() - timedelta(days=i)).strftime("%Y-%m-%d")
        try:
            results.append(await reconcile_day(db, bill_date))
            await db.commit()
        except Exception as e:
            await db.rollback()
            logger.error(f"[对账] {bill_date} 轧账异常: {e}", exc_info=True)
            results.append({"bill_date": bill_date, "error": str(e)[:200]})
    total = sum(r.get("diffs", 0) for r in results)
    if total:
        logger.error(f"[对账告警] 近 {settings.RECONCILE_LOOKBACK_DAYS} 日共发现 {total} 条差错，"
                     f"需在后台「对账差错」中人工处置")
    return {"days": results, "total_diffs": total}
