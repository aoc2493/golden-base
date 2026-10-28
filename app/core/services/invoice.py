"""B1：电子发票 —— 开票资格判定、字段校验、退款联动与台账序列化。

为什么单独一个 service 而不把规则写在 api/invoice.py 里：
同一套资格判据有三个消费方——用户端的「能否开票」查询、用户端的提交申请、
以及前端的按钮亮暗。写在路由里就只能被一个入口用，另两个入口各自复制一份，
而三份口径里只要有一份写差，就会出现「按钮是亮的、点了却报错」或
「按钮是灰的、其实能开」——前者让用户以为系统坏了，后者等于变相拒开发票
（《发票管理办法》第十九条：收取款项应当向付款方开具发票）。

本模块同时是后台开具台账的取值口径来源：brief()/detail() 决定运营看到什么，
api/admin.py 不再自行拼字段，避免用户端与后台对同一行数据给出两种说法。
"""
import logging
import re
import time
import secrets
from datetime import datetime
from decimal import Decimal

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.api.common import ErrorCode
from app.config import settings
from app.core.models import InvoiceRequest, Order
from app.core.services.config_helper import get_bool

logger = logging.getLogger(__name__)

# 申请状态。字符串常量而不是数字：台账要给人看，也要写进审计日志与告警，
# 数字状态在这些地方全都得再查一次对照表。
ST_PENDING = "pending"      # 待开具
ST_ISSUED = "issued"        # 已开具
ST_REJECTED = "rejected"    # 已驳回（用户可改正后重新提交，仍复用同一行）
ST_CANCELLED = "cancelled"  # 用户撤销 / 退款自动作废

# 可重新提交的状态：驳回与撤销都允许改抬头后再来一次。
# 不新建行而是改本行——order_id 上有唯一约束（一单一票），
# 松开约束就会让并发双击真的产生两条申请，进而可能开出两张发票。
REAPPLY_STATUSES = (ST_REJECTED, ST_CANCELLED)

# 纳税人识别号：统一社会信用代码 18 位，老税号 15 位，个别 20 位。
# 只校验形态不校验真伪（真伪要调税局接口，本项目不接）：形态校验能挡住
# 「漏了一位」「把 O 打成 0」这类最常见的输入错误，而这类错误的后果是
# 票开出来了却不能抵扣，必须红冲重开——一次红冲就是一次人工成本。
_RE_TAX_NO = re.compile(r"^[0-9A-Z]{15,20}$")
_RE_EMAIL = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

# 订单状态到「为什么不能开票」的映射。逐态给具体原因而不是统一一句「不符合条件」：
# 用户不知道自己该做什么（去付款？等退款结果？找客服？）时，只会重复点击然后投诉。
_STATUS_REASON = {
    "pending": "订单尚未支付成功，付款成功后即可申请开票",
    "refunded": "订单已退款，未实际收款不能开具发票",
    "refund_pending": "订单正在退款流程中，请等待退款结果后再申请",
    "cancelled": "订单已取消，无收款事实故不开具发票",
    "expired": "订单已过期未支付，无收款事实故不开具发票",
}


def gen_apply_no() -> str:
    """申请单号 IV + 年月日时分秒 + 6 位密码学随机数（与订单号 BZ 同范式）。

    用 secrets 而不是 random：单号可被用户看到，可预测的自增/伪随机序列
    等于把「平台一天开多少票」这个经营数据暴露出去。
    """
    return f"IV{time.strftime('%Y%m%d%H%M%S')}{secrets.randbelow(900000) + 100000}"


async def enabled(db: AsyncSession) -> bool:
    """开票入口是否开放。DB 的 invoice_enabled 可临时覆盖配置（与 refund_enabled 同范式）。

    关掉时前端必须显示原因与客服路径，不能只是让按钮消失：静默关闭在用户看来
    与「拒开发票」没有区别，而后者是《发票管理办法》第三十五条的罚则情形。
    """
    return await get_bool(db, "invoice_enabled", bool(settings.INVOICE_ENABLED))


def order_block(order: Order, inv: InvoiceRequest = None, *, now: datetime = None):
    """该订单能否开票。返回 (ErrorCode, 原因) 或 None（可申请）。

    /invoice/eligible 与 /invoice/apply 共用本函数，保证「按钮能点 ⟺ 接口放行」恒成立。
    inv 是该订单已有的申请行（可能为 None）：一单一票，已开具/待开具的都不放行，
    但驳回与撤销允许改正后复用同一行重新提交。
    """
    if order is None:
        return ErrorCode.ORDER_INVALID, "订单不存在"
    now = now or datetime.now()
    if order.status != "completed":
        return (ErrorCode.INVOICE_NOT_ELIGIBLE,
                _STATUS_REASON.get(order.status, f"订单状态为 {order.status}，暂不可开票"))
    # 0 元单（会员权益内生成的解读单、补偿单）没有收款事实，开票义务不成立。
    # 用 Decimal 比较而不是 float：金额判据一旦用浮点，0.00 与 0.004 的区别就说不清了。
    if order.amount is None or Decimal(str(order.amount)) <= Decimal("0"):
        return (ErrorCode.INVOICE_NOT_ELIGIBLE,
                "该订单实付 0 元（会员权益内生成或补偿单），无收款事实故不开具发票")
    if not order.paid_at:
        # 状态是 completed 却没有付款时间，说明数据本身不一致，不能凭猜测放行
        return (ErrorCode.INVOICE_NOT_ELIGIBLE,
                "订单缺少付款时间，请联系客服核实后开具（我们会照开，只是需要人工核对）")
    days = max(int(settings.INVOICE_APPLY_DAYS or 0), 1)
    age = (now - order.paid_at).days
    if age > days:
        return (ErrorCode.INVOICE_NOT_ELIGIBLE,
                f"该订单付款已超过 {days} 天，在线自助通道已关闭；开票义务仍然存在，"
                "请联系客服人工登记，我们会照开（跨期开票需财务专项处理，故不走自助）")
    if inv is not None and inv.status not in REAPPLY_STATUSES:
        if inv.status == ST_ISSUED:
            return (ErrorCode.INVOICE_DUPLICATED,
                    "该订单发票已开具；如需修改抬头请联系客服办理红字冲销后重开")
        return (ErrorCode.INVOICE_DUPLICATED,
                "该订单已提交开票申请，正在开具中；如需修改抬头请先撤销申请再重新提交")
    return None


def validate_apply(invoice_type: str, title: str, tax_no: str, email: str):
    """校验抬头/税号/邮箱，返回 (可读错误信息, 归一后的字段 dict)。

    归一化在后端做而不是信任前端：抬头两端空格、税号小写、邮箱大写都是常见输入，
    原样存进台账再交给财务，开出来的票就会带着这些瑕疵。
    """
    if invoice_type not in ("personal", "company"):
        return "发票类型不正确", None
    t = (title or "").strip()
    if not t:
        return "请填写发票抬头", None
    if len(t) > 100:
        return "发票抬头过长（不超过 100 字）", None
    tax = (tax_no or "").strip().upper()
    if invoice_type == "company":
        if not tax:
            return "企业发票必须填写纳税人识别号，否则开出的发票不能税前扣除", None
        if not _RE_TAX_NO.match(tax):
            return "纳税人识别号格式不正确（应为 15~20 位数字或大写字母）", None
    else:
        # 个人票不收税号：收了也用不上，而多收一项就多一项个人信息（个保法第六条最小必要）
        tax = ""
    e = (email or "").strip()
    if not e:
        return "请填写接收电子发票的邮箱", None
    if len(e) > 100 or not _RE_EMAIL.match(e):
        return "邮箱格式不正确，电子发票将无法送达", None
    return None, {"invoice_type": invoice_type, "title": t, "tax_no": tax, "email": e}


def notice(db_enabled: bool = True) -> dict:
    """开票须知。后端下发，前端不另抄一份。

    这些文字是平台向用户作出的承诺（几天内开、开什么票、超期怎么办），抄两份必然走偏：
    后端把时限从 3 天改成 5 天而前端还写着 3 天，用户按 3 天来催，那就是虚假告知。
    """
    return {
        "enabled": bool(db_enabled),
        "apply_days": max(int(settings.INVOICE_APPLY_DAYS or 0), 1),
        "promise_days": max(int(settings.INVOICE_ISSUE_PROMISE_DAYS or 0), 1),
        "item_name": (settings.INVOICE_ITEM_NAME or "").strip(),
        "invoice_kind": "增值税电子普通发票（与纸质发票具有同等法律效力）",
        "not_provided": "不提供增值税专用发票（需一般纳税人资质，如有需要请联系客服）",
        "lines": [
            f"付款成功后 {max(int(settings.INVOICE_APPLY_DAYS or 0), 1)} 天内可在线申请，"
            "超期请联系客服人工登记，开票义务不因超期而消失。",
            f"提交后 {max(int(settings.INVOICE_ISSUE_PROMISE_DAYS or 0), 1)} 个工作日内开具，"
            "开具后发送至您填写的邮箱。",
            "开票金额等于订单实付金额，不含已退款部分；0 元订单（会员权益内生成）无收款事实，不开具发票。",
            "一张订单只能开具一张发票；抬头或税号填写有误可先撤销申请再重新提交。",
            "订单退款后，待开具的申请会自动作废；已开具的发票需联系客服办理红字冲销。",
        ],
        "disabled_reason": "" if db_enabled else "开票申请通道临时关闭，请联系客服人工登记（我们仍会依法开具）",
    }


def _mask_email(email: str) -> str:
    """邮箱脱敏（后台列表用）。保留首 2 位与完整域名：运营要能一眼看出是不是同一个企业域，
    全打码就没法识别「同一家公司批量索票」这类需要人工复核的情形。"""
    e = (email or "").strip()
    if "@" not in e:
        return e[:2] + "***" if e else ""
    local, _, domain = e.partition("@")
    return f"{local[:2]}***@{domain}"


def _mask_title(title: str) -> str:
    """抬头脱敏（后台列表用）。个人抬头即真实姓名，与提现列表的实名脱敏同口径；
    企业抬头保留首 4 后 2 位，足够运营辨识是谁申请的。完整抬头只在
    详情接口（操作密码门禁 + 审计）下发——开票时照抄抬头，必须看明文。"""
    t = (title or "").strip()
    if not t:
        return ""
    if len(t) <= 6:
        return t[:2] + "***"
    return t[:4] + "***" + t[-2:]


def _mask_tax_no(tax_no: str) -> str:
    """税号脱敏（后台列表用）。统一社会信用代码/身份证号保留前 4 后 3 位。"""
    s = (tax_no or "").strip()
    if not s:
        return ""
    if len(s) <= 8:
        return s[:3] + "***"
    return s[:4] + "***" + s[-3:]


def brief(inv: InvoiceRequest, *, mask_email: bool = False,
          mask_pii: bool = False) -> dict:
    """台账列表行。用户端与后台列表共用，差别在邮箱/抬头/税号是否脱敏。

    mask_pii（后台列表用）：抬头（个人=真实姓名）与税号（个人可能填身份证号）
    属可识别个人信息，列表接口可分页遍历全部申请，与邮箱同口径脱敏；
    完整值走详情接口的门禁。"""
    return {
        "id": inv.id,
        "apply_no": inv.apply_no,
        "order_id": inv.order_id,
        "order_no": inv.order_no,
        "user_id": inv.user_id,
        "amount": float(inv.amount) if inv.amount is not None else None,
        "product_name": inv.product_name,
        "invoice_type": inv.invoice_type,
        "title": _mask_title(inv.title) if mask_pii else inv.title,
        "tax_no": _mask_tax_no(inv.tax_no) if mask_pii else inv.tax_no,
        "email": _mask_email(inv.email) if mask_email else inv.email,
        "status": inv.status,
        "need_red_flush": int(inv.need_red_flush or 0),
        "created_at": inv.created_at.strftime("%Y-%m-%d %H:%M") if inv.created_at else None,
    }


def detail(inv: InvoiceRequest) -> dict:
    """台账详情：在列表字段之上补齐开具结果与处置留痕。"""
    d = brief(inv)
    d.update({
        "remark": inv.remark,
        "item_name": inv.item_name,
        "invoice_no": inv.invoice_no,
        "invoice_code": inv.invoice_code,
        "issued_at": inv.issued_at.strftime("%Y-%m-%d %H:%M") if inv.issued_at else None,
        "delivery": inv.delivery,
        "invoice_file": inv.invoice_file,
        "reject_reason": inv.reject_reason,
        "handler": inv.handler,
        "updated_at": inv.updated_at.strftime("%Y-%m-%d %H:%M") if inv.updated_at else None,
    })
    return d


def user_detail(inv: InvoiceRequest) -> dict:
    """P3 修复（用户端字段收敛）：detail() 是管理台账口径，handler（处置人账号）、
    invoice_file（内部文件路径）、delivery（内部投递留痕）属运营侧信息，
    不应下发给普通用户。用户详情基于 brief + 开具结果字段，剔除内部三件套。"""
    d = detail(inv)
    for k in ("handler", "invoice_file", "delivery"):
        d.pop(k, None)
    return d


async def find_by_order(db: AsyncSession, order_id: int):
    """按订单取申请行（一单一票，最多一条）。"""
    return (await db.execute(select(InvoiceRequest).where(
        InvoiceRequest.order_id == order_id))).scalar_one_or_none()


async def on_order_refunded(db: AsyncSession, order: Order) -> str:
    """退款成功后处理该订单的发票申请。返回异常描述（空串=正常）。

    挂在 fulfillment.revoke_refunded_order 里，一处覆盖全部 5 条退款路径
    （用户自助退款、管理员兜底退款、微信退款回调、失败报告自动退款、退款失败重试）。
    放在各调用点上必然漏，而漏掉的那一条正是「钱退了票还开着」的成因。

    两个分支都不能不做：
      · 待开具 → 自动作废。交易已经不存在，此时开票就是为不存在的交易开具发票（虚开）。
      · 已开具 → 置 need_red_flush 并按 ERROR 告警。已交付的发票不会随退款自动消失，
        必须开红字发票冲销，否则平台账面收入与税局申报收入长期不符；
        红冲只能在税局系统人工操作，没有自动通道，所以必须把人叫来
        （B2 的告警 Handler 会把这条 ERROR 推到企微/钉钉群）。
    """
    try:
        inv = await find_by_order(db, order.id)
        if inv is None:
            return ""
        if inv.status == ST_PENDING:
            inv.status = ST_CANCELLED
            inv.reject_reason = "订单已退款，交易不成立，申请自动作废"
            inv.handler = "system"
            logger.info(f"[发票] 订单退款，待开具申请自动作废 apply_no={inv.apply_no} order={order.order_no}")
        elif inv.status == ST_ISSUED:
            inv.need_red_flush = 1
            logger.error(f"[发票告警] 订单已退款但发票已开具，需人工办理红字冲销 "
                         f"apply_no={inv.apply_no} order={order.order_no} "
                         f"invoice_no={inv.invoice_no or '（未回填）'} amount={inv.amount}")
        await db.flush()
        return ""
    except Exception as e:
        logger.error(f"[发票] 退款联动处理失败 order_id={order.id}: {e}", exc_info=True)
        # 审计 M3：原始异常只入日志（已含堆栈），对外文案统一，避免泄露内部细节
        return "发票联动处理失败，请稍后重试或联系客服"


async def mark_issued(db: AsyncSession, inv: InvoiceRequest, *, invoice_no: str,
                      invoice_code: str = None, delivery: str = "email",
                      invoice_file: str = None, handler: str = "admin") -> None:
    """回填开具结果。

    need_red_flush 在这里清零：若这条申请曾被退款钩子置位（先退款后置开具的异常时序），
    开具动作本身就说明财务已经人工核对过，不该把旧标记带进新状态。
    """
    inv.status = ST_ISSUED
    inv.invoice_no = invoice_no
    inv.invoice_code = invoice_code or None
    inv.delivery = delivery
    inv.invoice_file = invoice_file or None
    inv.issued_at = datetime.now()
    inv.handler = handler
    inv.reject_reason = None
    inv.need_red_flush = 0
    await db.flush()


async def ensure_order_owned(db: AsyncSession, order_id: int, user_id: int):
    """取属于该用户的订单。返回 None 表示不存在或不属于他——两种情况给同一句话，
    不区分「订单不存在」与「不是你的订单」：后者会泄露订单 id 是否存在的枚举信息。"""
    return (await db.execute(select(Order).where(
        Order.id == order_id, Order.user_id == user_id))).scalar_one_or_none()
