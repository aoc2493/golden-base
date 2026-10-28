"""B1 开票资格判据与退款联动的回归测试。

为什么这块必须有测试：开票是法定义务（《发票管理办法》第十九条），判据错两个方向
都出事——放宽了就是为不存在的交易开具发票（虚开），收紧了就是变相拒开发票（第三十五条罚则）。
而 `/invoice/eligible` 与 `/invoice/apply` 共用 order_block 这一个纯函数，
只要它退化，两个入口一起退化，前端与后端还会给出同一个错误结论，线上看不出来。

写法说明：资格判据刻意做成纯函数（吃 Order/InvoiceRequest 实例，不查库），
所以这里绝大多数用例不需要 HTTP，也不需要支付渠道——
本机没有微信商户配置，后台兜底退款会停在 4006「支付平台退款调用失败」，
用 HTTP 验不到 refunded 分支；把 refunded 直接写进订单状态再判，才是这条规则的真实测试。
"""
from datetime import datetime, timedelta
from decimal import Decimal

import pytest
from sqlalchemy.exc import IntegrityError

from app.core.api.common import ErrorCode
from app.core.models import InvoiceRequest, Order, User
from app.core.services import invoice as svc


def _order(status="completed", amount="39.90", paid_days_ago=0, **kw):
    """构造未入库的订单实例：order_block 只读属性，不落库也能判。"""
    if "paid_at" not in kw:
        kw["paid_at"] = None if paid_days_ago is None else (
            datetime.now() - timedelta(days=paid_days_ago))
    return Order(id=kw.pop("id", 1), order_no=kw.pop("order_no", "BZ20261028TEST000001"),
                 user_id=kw.pop("user_id", 7), product_name="测试商品",
                 amount=Decimal(amount), status=status, **kw)


def _inv(status=svc.ST_PENDING, **kw):
    kw.setdefault("title", "张三")
    kw.setdefault("email", "a@example.com")
    return InvoiceRequest(id=kw.pop("id", 501), apply_no="IV20261028TEST000001",
                          order_id=1, order_no="BZ20261028TEST000001", user_id=7,
                          amount=Decimal("39.90"), invoice_type="personal",
                          status=status, **kw)


# ==================== 一、订单状态：非 completed 一律不开 ====================

@pytest.mark.parametrize("status,expect_kw", [
    ("pending", "尚未支付"),
    ("refunded", "已退款"),
    ("refund_pending", "退款流程中"),
    ("cancelled", "已取消"),
    ("expired", "已过期"),
])
def test_non_completed_orders_are_blocked_with_specific_reason(status, expect_kw):
    """每个不可开票状态都要给出**该状态自己的**原因，而不是一句「不符合条件」。

    断言文案里关键词：用户看到「尚未支付」会去付款，看到「已退款」才会去找客服；
    统一一句「暂不可开票」只会让用户重复点击。退化成统一文案即为本用例失败。
    """
    block = svc.order_block(_order(status=status))
    assert block is not None, f"状态 {status} 竟被放行"
    code, reason = block
    assert code == ErrorCode.INVOICE_NOT_ELIGIBLE
    assert expect_kw in reason, f"{status} 的原因文案没有区分度: {reason}"


def test_refunded_order_cannot_be_invoiced():
    """钱已退回，收款事实消失，此时开票即为不存在的交易开具发票。"""
    block = svc.order_block(_order(status="refunded"))
    assert block[0] == ErrorCode.INVOICE_NOT_ELIGIBLE
    assert "不能开具发票" in block[1]


def test_completed_order_without_paid_at_is_blocked():
    """completed 却没有 paid_at 说明数据不一致，不能凭猜测放行。"""
    assert svc.order_block(_order(paid_at=None)) is not None


def test_zero_amount_order_is_blocked():
    """0 元单（会员权益内生成、补偿单）无收款事实，开票义务不成立。"""
    for amount in ("0.00", "0", "-1.00"):
        block = svc.order_block(_order(amount=amount))
        assert block is not None, f"金额 {amount} 竟被放行"
        assert "0 元" in block[1], f"零金额文案未说明原因: {block[1]}"


def test_missing_order_is_rejected_not_crashed():
    """订单查不到（不存在或不属于该用户）时给 4002，而不是抛属性错误冒成 500。"""
    assert svc.order_block(None) == (ErrorCode.ORDER_INVALID, "订单不存在")


# ==================== 二、自助通道时限：超期关闭但义务不消失 ====================

def test_apply_window_blocks_only_after_the_configured_days():
    """时限判据要跟着配置走，且超期文案必须保留人工通道。

    只写「已超过申请期限」等于告诉用户开不了了——那是拒开的表述；
    开票义务不因超期而消失，跨期只是需要财务专项处理。
    """
    from app.config import settings
    days = max(int(settings.INVOICE_APPLY_DAYS or 0), 1)
    assert svc.order_block(_order(paid_days_ago=days - 1)) is None, "期内就被拦了"
    block = svc.order_block(_order(paid_days_ago=days + 1))
    assert block is not None, f"付款 {days + 1} 天（配置 {days} 天）仍被放行"
    assert "联系客服" in block[1] and "照开" in block[1], f"超期文案未保留人工通道: {block[1]}"


def test_block_accepts_injected_now_for_determinism():
    """order_block 支持注入 now：时限判据可被确定性测试，不依赖跑测试的当天。"""
    old = datetime(2020, 1, 1)
    assert svc.order_block(_order(paid_at=old), now=datetime(2026, 1, 1)) is not None
    assert svc.order_block(_order(paid_at=old), now=old + timedelta(days=1)) is None


# ==================== 三、一单一票：已申请的行挡住第二次 ====================

@pytest.mark.parametrize("inv_status,expect_code", [
    (svc.ST_ISSUED, ErrorCode.INVOICE_DUPLICATED),
    (svc.ST_PENDING, ErrorCode.INVOICE_DUPLICATED),
])
def test_existing_application_blocks_reapply(inv_status, expect_code):
    """已开具/待开具都不放行：同一订单开两张票属虚开。"""
    block = svc.order_block(_order(), _inv(status=inv_status))
    assert block is not None and block[0] == expect_code


@pytest.mark.parametrize("inv_status", [svc.ST_REJECTED, svc.ST_CANCELLED])
def test_rejected_or_cancelled_application_can_be_resubmitted(inv_status):
    """驳回与撤销必须能改抬头再来一次，否则用户填错一个字就只能永远开不出票。

    这条与上一条成对：只测「挡得住重复」会退化成「任何已有申请都拒绝」，
    把用户永远锁死；只测「能重提」则会放开虚开。
    """
    assert svc.order_block(_order(), _inv(status=inv_status)) is None


def test_clean_completed_order_is_allowed():
    """正向基线：已支付、有金额、在期限内、无历史申请 → 放行。

    没有这条，上面所有「拒绝」断言都可能只是「永远拒绝」的假阳性。
    """
    assert svc.order_block(_order()) is None


# ==================== 四、抬头校验与归一化 ====================

def test_company_invoice_requires_well_formed_tax_no():
    for tax, ok in [("", False), ("91330100MA2XXXXX1A", True), ("91330100", False),
                    ("91330100MA2XXXXX1a", True), ("91330100MA2XXXXX1!", False)]:
        msg, norm = svc.validate_apply("company", "杭州某某科技有限公司", tax, "a@example.com")
        assert ok == (msg is None), f"税号 {tax!r} 期望放行={ok}，实际 msg={msg}"
        if ok:
            assert norm["tax_no"] == tax.upper(), "小写税号未归一为大写"


def test_personal_invoice_ignores_tax_no():
    """个人票不采集税号：多收一项就多一项个人信息（《个保法》第六条最小必要）。"""
    msg, norm = svc.validate_apply("personal", "张三", "91330100MA2XXXXX1A", "a@example.com")
    assert msg is None
    assert norm["tax_no"] == "", f"个人票仍把税号存进台账: {norm}"


def test_title_and_email_are_normalized_or_rejected():
    assert svc.validate_apply("personal", "  张三  ", "", "a@example.com")[1]["title"] == "张三"
    assert svc.validate_apply("personal", "", "", "a@example.com")[0]
    assert svc.validate_apply("personal", "张三", "", "not-an-email")[0]
    assert svc.validate_apply("personal", "张三", "", "A@EXAMPLE.COM")[1]["email"] == "A@EXAMPLE.COM"
    assert svc.validate_apply("unknown", "张三", "", "a@example.com")[0], "非法发票类型未拒绝"
    assert svc.validate_apply("company; DROP TABLE", "张三", "", "a@example.com")[0]


# ==================== 五、退款联动：5 条退款路径共用的一处钩子 ====================

async def _seed_user_and_order(db, status="completed"):
    db.add(User(id=7, nickname="开票测试"))
    order = Order(order_no="BZ20261028TEST000001", user_id=7, product_name="测试商品",
                  amount=Decimal("39.90"), status=status, paid_at=datetime.now())
    db.add(order)
    await db.flush()
    return order


async def test_refund_cancels_pending_application(db):
    """待开具 + 订单退款 → 自动作废。不作废就是给一笔已退回的交易开票。"""
    order = await _seed_user_and_order(db)
    db.add(InvoiceRequest(apply_no="IV20261028TEST000001", order_id=order.id,
                          order_no=order.order_no, user_id=7, amount=order.amount,
                          invoice_type="personal", title="张三", email="a@example.com",
                          status=svc.ST_PENDING))
    await db.flush()
    assert await svc.on_order_refunded(db, order) == ""
    inv = await svc.find_by_order(db, order.id)
    assert inv.status == svc.ST_CANCELLED
    assert inv.handler == "system", f"自动作废未留系统处置痕迹: {inv.handler}"
    assert "退款" in inv.reject_reason


async def test_refund_of_issued_application_flags_red_flush(db, caplog):
    """已开具 + 订单退款 → 置红冲标记并按 ERROR 告警（把财务叫来）。

    已交付的发票不会随退款消失，不冲销则平台收入与税局申报长期不符；
    红冲只能在税局系统人工做，所以这里必须落 ERROR 日志给告警 Handler 兜。
    """
    order = await _seed_user_and_order(db)
    db.add(InvoiceRequest(apply_no="IV20261028TEST000001", order_id=order.id,
                          order_no=order.order_no, user_id=7, amount=order.amount,
                          invoice_type="personal", title="张三", email="a@example.com",
                          status=svc.ST_ISSUED, invoice_no="01234567"))
    await db.flush()
    with caplog.at_level("ERROR"):
        assert await svc.on_order_refunded(db, order) == ""
    inv = await svc.find_by_order(db, order.id)
    assert inv.need_red_flush == 1, "已开票订单退款未置红冲标记"
    assert inv.status == svc.ST_ISSUED, "已开具的票不能被退款钩子悄悄改成别的状态"
    assert "红字冲销" in caplog.text


async def test_refund_without_application_is_quiet(db):
    order = await _seed_user_and_order(db)
    assert await svc.on_order_refunded(db, order) == ""
    assert await svc.find_by_order(db, order.id) is None


# ==================== 六、一单一票靠约束，不靠先查后插 ====================

async def test_two_applications_on_one_order_hit_the_unique_constraint(db):
    """order_id 唯一约束必须真实存在。

    接口层是先 SELECT 判重再 INSERT，两个并发请求能同时穿过判重；
    松开约束就是真的两行申请、两张票（虚开）。这里绕过判重直插第二行，撞的就是约束。
    """
    order = await _seed_user_and_order(db)
    db.add(InvoiceRequest(apply_no="IV20261028TEST000001", order_id=order.id,
                          order_no=order.order_no, user_id=7, amount=order.amount,
                          invoice_type="personal", title="张三", email="0@example.com",
                          status=svc.ST_PENDING))
    await db.flush()
    db.add(InvoiceRequest(apply_no="IV20261028TEST000002", order_id=order.id,
                          order_no=order.order_no, user_id=7, amount=order.amount,
                          invoice_type="personal", title="张三", email="1@example.com",
                          status=svc.ST_PENDING))
    with pytest.raises(IntegrityError):
        await db.flush()


async def test_ensure_order_owned_does_not_leak_other_users_orders(db):
    """取不到别人的订单，且与「订单不存在」给同一句话——否则订单 id 可被枚举。"""
    order = await _seed_user_and_order(db)
    assert (await svc.ensure_order_owned(db, order.id, 7)) is not None
    assert await svc.ensure_order_owned(db, order.id, 999) is None
    assert await svc.ensure_order_owned(db, 10 ** 9, 7) is None


# ==================== 七、台账序列化：内部字段与明文 PII 不外泄 ====================

def test_user_detail_drops_internal_fields():
    """用户详情不得带 handler（处置人账号）、invoice_file、delivery（内部留痕）。"""
    d = svc.user_detail(_inv(status=svc.ST_ISSUED, invoice_no="01234567",
                              handler="finance-01",
                              invoice_file="/data/invoice/1.pdf", delivery="email:内部群"))
    for k in ("handler", "invoice_file", "delivery"):
        assert k not in d, f"内部字段 {k} 下发给了普通用户"
    assert d["invoice_no"] == "01234567", "开具结果字段属于用户该看到的，不应被一并剔除"


def test_admin_list_masks_pii_but_detail_keeps_plaintext():
    """后台列表可分页遍历全部申请，抬头/税号/邮箱按 PII 脱敏；明文只走详情门禁。"""
    inv = _inv(title="杭州某某科技有限公司", tax_no="91330100MA2XXXXX1A",
               email="zhangsan@company.com")
    masked = svc.brief(inv, mask_email=True, mask_pii=True)
    assert masked["email"] == "zh***@company.com", f"邮箱脱敏丢了域名: {masked['email']}"
    assert "***" in masked["title"] and "公司" in masked["title"]
    assert "***" in masked["tax_no"]
    for field in ("email", "title", "tax_no"):
        assert masked[field] != getattr(inv, field)
    plain = svc.detail(inv)
    assert plain["email"] == "zhangsan@company.com", "详情接口应下发明文供开票照抄"


async def test_mark_issued_clears_stale_red_flush(db):
    """先退款后置开具的异常时序里，开具动作本身说明财务已人工核对，旧标记不得残留。"""
    order = await _seed_user_and_order(db)
    inv = InvoiceRequest(apply_no="IV20261028TEST000001", order_id=order.id,
                         order_no=order.order_no, user_id=7, amount=order.amount,
                         invoice_type="personal", title="张三", email="a@example.com",
                         status=svc.ST_CANCELLED, need_red_flush=1, reject_reason="旧驳回理由")
    db.add(inv)
    await db.flush()
    await svc.mark_issued(db, inv, invoice_no="99998888")
    assert (inv.status, inv.need_red_flush, inv.reject_reason) == ("issued", 0, None)
    assert inv.issued_at is not None


def test_apply_no_is_unpredictable_and_stable_shaped():
    """申请单号可被用户看到：自增或弱随机会把「一天开多少票」这个经营数据漏出去。

    断言形态（IV + 14 位时间 + 6 位随机）与随机位的散布度；后缀若取值过窄
    （例如只有几位有效熵），别人的单号就能被推算出来。
    """
    nos = [svc.gen_apply_no() for _ in range(100)]
    assert all(n.startswith("IV") and len(n) == 22 and n[2:].isdigit() for n in nos)
    # 随机后缀落在 6 位十进制全区间：900000 个取值里抽 100 个，撞车本就罕见，
    # 所以这里断言的是「取值够散」，而不是「100 次绝不重复」（那会随机的概率性误报）。
    suffixes = {int(n[16:]) for n in nos}
    assert len(suffixes) >= 95, f"随机后缀取值过窄（{len(suffixes)}/100），可被推算"
    assert all(100000 <= s <= 999999 for s in suffixes)
