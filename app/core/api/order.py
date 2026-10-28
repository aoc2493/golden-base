import json
import logging
from datetime import datetime, timedelta
from fastapi import APIRouter, BackgroundTasks, Depends, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, func
from app.core.database import get_db
from app.core.models import User, Order, Product, ResultCache, Report, Refund
from app.core.schemas import OrderCreateRequest, RefundRequest
from app.core.auth import get_current_user, redis_client
from app.core.utils.payment import PaymentService, create_payment, apply_refund, gen_refund_no
from app.core.api.common import success, error, ErrorCode, get_client_ip, redis_rate_limit, to_money
from app.core.services.config_helper import get_bool
from app.core.services.fulfillment import revoke_refunded_order, order_delivers_report
from app.core.plugin_contract import PluginError
from app.plugins import registry
from app.core.services.membership import assert_can_buy
from app.core.services.payment_sync import sync_order_for_user
from app.core.services import consent as consent_svc
from app.core.services import minor_guard as guard_svc
from app.core.services import distribution_compliance as compliance_svc
from app.config import settings

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/order", tags=["订单"])
STATUS_TEXT = {
    "pending": "待支付", "completed": "已完成", "refunded": "已退款",
    "refund_pending": "退款中", "expired": "已过期", "cancelled": "已取消",
}
# L22/L24：交付不由 reports 表跟踪的 SKU 统一登记在 fulfillment.NO_REPORT_DELIVERY_SKUS，
# 本文件的自助退款判据与插件的报告自愈守卫共用那一份，不在这里另立集合：
# 两处要回答的是同一个事实问题（内容交付痕迹是否在 reports 表），答案必须一致。
# 新增同类 SKU 只需改登记处那一行。


def _norm_biz(val) -> dict:
    """业务快照归一化，用于订单复用比对（JSON 列可能存为 dict 也可能存为 str）"""
    if isinstance(val, str) and val:
        try:
            val = json.loads(val)
        except json.JSONDecodeError:
            return {}
    return val if isinstance(val, dict) else {}


def _gate_subjects(input_snapshot, biz_data: dict) -> list:
    """A8：从本次下单的业务快照里取出全部会被处理的出生信息，交给年龄门槛判定。

    为什么按快照取而不按 SKU 列举：快照是真正会落库并送去生成报告的数据，
    按 SKU 写白名单则新增一个带出生信息的商品时必须记得改这里，漏改就是门槛少拦一条路径。
    实时测算/日常工具的快照里没有出生信息，自然返回空列表——不采集出生信息就不需要监护人同意，
    也不需要他人出生信息告知（两项门槛拦的都是「处理出生信息信息」这个动作）。
    双人内容（sides）与双人解读（male/female）恒为两人，两人出生信息都要过 <14 岁的判定。
    """
    out = []
    src = input_snapshot if isinstance(input_snapshot, dict) else {}
    containers = [src]
    sides = (biz_data or {}).get("sides")
    if isinstance(sides, list):
        containers.extend([s for s in sides if isinstance(s, dict)])
    for k in ("male", "female"):
        s = (biz_data or {}).get(k)
        if isinstance(s, dict):
            containers.append(s)
    seen = set()
    for c in containers:
        bd = str(c.get("birth_date") or "").strip()
        if not bd:
            continue
        item = (bd, str(c.get("calendar_type") or "solar").strip().lower())
        # 双人内容的 input_snapshot 与 biz_data 是同一个对象，去重避免同一份出生信息重复留痕
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


# 卡券兑换单的支付渠道标识（与 services.card.CARD_PAY_CHANNEL 一致）。
# 刻意写成字面量而非 import：卡券模块可以单独回滚删除，若此处 import 它，
# 一旦模块缺失整个 app 都起不来 —— 一个可选业务模块不能把整站带崩。
CARD_CHANNEL = "card"


def _self_refund_block(order: Order, report):
    """自助退款资格的唯一判据（L22/L23）：返回不可退款的原因文案，None 表示资格通过。

    POST /order/refund 与 /order/list、/order/{id} 的 can_refund 必须共用本函数。
    三处各写一份的条件曾长期互相矛盾：
      - 实时测算单（live_once）的交付痕迹在 result_cache 而不在 reports，接口按黑名单式
        「有报告且已查看才拒绝」判断，等于无条件放行退款：用户看完测算结果（第三方接口
        已计费、测算结果缓存还留着）再全额退回，可反复下单-查看-退款循环套利（L22）；
        而前端 can_refund 是白名单式「有报告且未查看才允许」，从不显示退款按钮，
        两端结论完全相反。
      - 会员 0 元解读单（ensure-report 创建）前端给出退款按钮，接口却因「无实际支付
        金额」必然拒绝，用户点了只会收到报错，永远退不掉（L23）。
    report 为该订单的 Report 行，可为 None：解读类订单查不到报告行说明报告从未生成
    （生成任务丢失，见插件报告守卫的自愈逻辑），用户付了钱什么都没拿到，必须放行。
    """
    if order.status != "completed":
        return "当前订单状态不支持退款"
    if order.product_type not in ("single", "report"):
        return "会员与单日虚拟内容不支持自助退款，可联系客服处理"
    # L22：交付物不是报告（实时拉取型等）无法据 viewed_at 判断是否已消费，走客服兜底
    if not order_delivers_report(order):
        return "该商品不支持自助退款，可联系客服处理"
    # 无真实支付流水的订单不存在可退的钱：会员免费生成的 0 元解读单
    # （ensure-report 创建，amount=0、pay_channel="member"、pay_trade_no 为空）同样是
    # product_type="single"，不拦住会向支付平台发起无效退款并产生脏退款单。
    # 卡券兑换单（pay_channel='card'）是 0 元权益载体，站内不存在任何真实资金流。
    # 它虽然也会被下面「金额<=0」那句拦住，但提示语是「无需退款」，客服会理解成
    # 「可以退但没必要」，而不是「不能退」；更要紧的是一旦将来给卡券单补上金额，
    # 退款成功就会触发 revoke_refunded_order 撤销用户已到账的权益，而卡券已是
    # used 无法重兑 —— 用户白丢权益且没有任何恢复路径。这里显式前置拦截。
    if (order.pay_channel or "") == CARD_CHANNEL:
        return "卡券兑换订单不支持退款，请联系购买渠道"
    if not order.pay_trade_no or to_money(order.amount) <= 0:
        return "该订单无实际支付金额，无需退款"
    if not order.paid_at or order.paid_at + timedelta(days=settings.REFUND_DAYS) < datetime.now():
        return "已超过退款期限"
    if report is not None and report.viewed_at is not None:
        return "已查看报告不支持退款"
    return None


@router.post("/create")
async def create_order(req: OrderCreateRequest, request: Request,
                       db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    """创建订单（价格以后端商品表为准；N13 防重复下单；N1 真实 IP）"""
    paid_enabled = await get_bool(db, "paid_reports_enabled", True)
    if not paid_enabled:
        return error(ErrorCode.PAYMENT_FAILED, "付费功能暂未开放")

    # N13：下单频率限制，防双击/刷单
    allowed = await redis_rate_limit(
        redis_client, f"rate:order:{user.id}", settings.RATE_LIMIT_ORDER_PER_MIN, 60)
    if not allowed:
        return error(ErrorCode.RATE_LIMIT, "操作过于频繁，请稍后再试")

    # A6（个保法第十五条）：已撤回个人信息处理同意的用户不得再发起新的付费处理。
    # 放在限流之后、商品查询之前：限流先拦住刷单，避免撤回校验被当成免费探测接口反复打。
    # 已成交订单不在此列（包括会员 0 元解读单）：已付钱的内容必须继续交付，
    # 收回已收款订单的履约比隐私问题更严重；彻底停止处理的路径是注销账号。
    deny = await consent_svc.ensure_privacy_consent(db, user.id)
    if deny:
        return error(ErrorCode.NO_PERMISSION, deny)

    # A8（未成年人网络保护条例第四十三条）：付款人须为成年人，未成年人禁充值。
    # 放在隐私校验之后、商品查询之前：这两道都是「该不该让你下单」的前置门，
    # 先于任何计费/库存/权益查询，避免被拦的请求白白消耗下游资源。
    # 周岁每次现算（不存 is_adult 标记），17 岁声明的人在 18 岁生日当天自动放行。
    gate = guard_svc.gate_payer(user)
    if gate:
        code, msg, data = gate
        return error(code, msg, data)

    # M3①（第五十六条第3款）：支付前免责勾选的服务端闸门。留痕由前端经
    # POST /consent/sign 写入 DOC_PAYMENT_DISCLAIMER，此处校验最新一行是否为已同意。
    # 默认由 ENFORCE_PAYMENT_DISCLAIMER=False 关闭以兼容无签署 UI 的占位前端；
    # 运营接好勾选前端后置 True，未签署者即被挡在下单前。放在年龄门槛之后、商品查询之前，
    # 与隐私/年龄两道前置门同序（都是「该不该让你下单」的判定，先于任何计费/库存查询）。
    if settings.ENFORCE_PAYMENT_DISCLAIMER:
        if not await compliance_svc.has_signed(db, user.id, compliance_svc.DOC_PAYMENT_DISCLAIMER):
            return error(ErrorCode.NO_PERMISSION, "请先阅读并同意支付免责与虚拟商品规则后再下单")

    product = None
    if req.sku_code:
        product = (await db.execute(
            select(Product).where(Product.sku_code == req.sku_code, Product.enabled == 1))).scalar_one_or_none()
    elif req.product_id:
        product = (await db.execute(
            select(Product).where(Product.id == req.product_id, Product.enabled == 1))).scalar_one_or_none()
    if not product:
        return error(ErrorCode.PRODUCT_NOT_FOUND, "商品不存在或已下架")
    if (product.product_type or "") == "timepass":
        return error(ErrorCode.PARAM_ERROR, "该商品为卡券专享，请通过卡券兑换使用")
    sku = product.sku_code
    ptype = product.product_type or "report"
    channel = req.channel
    if channel not in ("wechat", "alipay"):
        return error(ErrorCode.PARAM_ERROR, "请选择支付方式")
    block_reason = await assert_can_buy(db, user.id, sku)
    if block_reason:
        return error(ErrorCode.PARAM_ERROR, block_reason)
    ua = (request.headers.get("user-agent") or "").lower()
    in_wechat = "micromessenger" in ua
    if in_wechat and channel == "alipay":
        return error(ErrorCode.PARAM_ERROR, "微信内暂不支持支付宝，请选择微信支付，或在浏览器中打开使用支付宝")
    if user.inviter_id == user.id:
        return error(ErrorCode.PARAM_ERROR, "下单异常，请刷新后重试")

    # N6/N13：同一用户同一 SKU 存在未支付订单时直接复用，避免重复建单
    existing = (await db.execute(
        select(Order).where(Order.user_id == user.id, Order.sku_code == sku,
                            Order.status == "pending").order_by(Order.id.desc()))).scalars().first()

    input_snapshot = None
    biz_data = dict(req.biz_data or {})
    cache_id_val = None
    entry, cap = registry.cap_by_sku(sku)
    if ptype == "single" and entry is not None and cap is not None:
        # 单次内容的业务快照（入参校验 / 前置缓存 / 归一 / biz_key）全部由插件钩子产出，
        # core 不认识任何具体业务。
        try:
            prep = await entry.service.prepare_order(
                cap,
                {"result_ref_id": req.result_ref_id,
                 "biz_data": dict(req.biz_data or {})},
                user, db)
        except PluginError as pe:
            return error(pe.code, pe.msg, pe.data)
        biz_data = prep.biz_data
        input_snapshot = prep.input_snapshot
        cache_id_val = prep.result_ref_id
    elif ptype == "report" and req.result_ref_id:
        # 通用报告型：绑定前置计算缓存（一份快照对应一份报告）
        cobj = (await db.execute(select(ResultCache).where(
            ResultCache.id == req.result_ref_id,
            ResultCache.user_id == user.id))).scalar_one_or_none()
        if not cobj:
            return error(ErrorCode.CACHE_NOT_FOUND, "测算数据不存在，请重新填写")
        if cobj.expire_at < datetime.now():
            return error(ErrorCode.CACHE_EXPIRED, "测算数据已过期，请重新填写")
        input_snapshot = cobj.input_data
        if isinstance(input_snapshot, str):
            input_snapshot = json.loads(input_snapshot)
        biz_data["cache_id"] = cobj.id
        cache_id_val = cobj.id

    # 会员一律全价（方案B）：不做升级补差价，会员单恒按商品挂牌全价扣款；
    # 升档时旧档剩余整天由 grant_membership 顺延叠加到新档到期日，不在价格上折算。
    amount = to_money(product.price)
    # 加固：真实付费档位不允许 0 价/负价成交。商品表一旦误配置成 0 元，
    # 下单→回调金额校验（0==0）会全绿放行，等于免费发放付费权益且无法退款拦截。
    # 这里在拉起支付前 fail-closed；免费载体只应是卡券 0 元单与会员 0 元解读单。
    if ptype in ("single", "membership", "report") and amount <= 0:
        return error(ErrorCode.PARAM_ERROR, "商品价格异常，请联系客服")
    # N6：复用未支付订单，但必须真正校验业务快照一致。
    # 原实现只比对 sku_code，注释却声称“仅当业务快照一致时”，实际无任何比对，导致：
    #   ① 商品改价后复用旧 pending 单 → 本接口返回新价 amount，而支付平台按库里旧价扣款；
    #   ② 用户换了出生信息/换了双人内容对象再购买 → 复用的旧单仍带旧 input_snapshot，
    #      付款后生成的是上一个计算结果的报告（数据张冠李戴）。
    # 快照不一致时作废旧单并新建，保证“所见价=所扣价、所购内容=所得报告”。
    order = None
    if existing:
        # P2 修复（双渠道重复付款）：快照比对加入 pay_channel——原实现复用旧 pending 单时
        # 直接改写 pay_channel，旧渠道侧（微信 prepay/支付宝待支付单）仍挂在平台上，
        # 用户两个渠道都能完成支付，第二笔回调撞上已完成订单即成双收款且无法自助退款。
        # 渠道变更视为快照不一致：作废旧单、按新渠道新建。
        same_snapshot = (
            existing.product_id == product.id
            and existing.pay_channel == channel
            and to_money(existing.amount) == amount
            and (existing.result_ref_id or None) == cache_id_val
            and _norm_biz(existing.biz_data) == _norm_biz(biz_data)
            and _norm_biz(existing.input_snapshot) == _norm_biz(input_snapshot)
        )
        if same_snapshot:
            order = existing
        else:
            existing.status = "cancelled"
            existing.fail_reason = (f"业务快照或支付渠道已变更（{existing.pay_channel}→{channel}），"
                                    f"重新下单")
            logger.info(f"未支付订单快照不一致，作废旧单 order_no={existing.order_no} sku={sku}")
    if order is None:
        order = Order(
            order_no=PaymentService.generate_order_no(), user_id=user.id, product_id=product.id,
            sku_code=sku, product_type=ptype, product_name=product.name, amount=amount,
            status="pending", pay_channel=channel,
            result_ref_id=cache_id_val,
            input_snapshot=input_snapshot, biz_data=biz_data if biz_data else None,
            inviter_id=user.inviter_id,
            # 双向定位快照：user_id + 下单时登录标识共同钉死买家，开票/退款/客服追踪可双向回溯
            login_id_type=user.last_login_type, login_id_value=user.last_login_value)
        db.add(order)
        await db.flush()

    # N1：取用户真实公网 IP
    client_ip = get_client_ip(request)
    # A8（个保法第三十一条）：未成年人不满 14 周岁须监护人同意；提交他人出生信息须先告知。
    # 刻意放在订单行已建、拉起支付之前：留痕要带 order_id，而订单的 input_snapshot/biz_data
    # 里存着本次处理的确切出生信息，两者一对就能完整重建「何时、何人、为哪个出生信息、确认了什么」。
    # 被拦时订单停在 pending（未发起任何支付、未动钱），用户补齐确认后重试会由 N6 复用同一张单。
    bio_gate = await guard_svc.gate_bio(
        db, user, _gate_subjects(input_snapshot, biz_data),
        guardian_consent=req.guardian_consent, third_party_consent=req.third_party_consent,
        ip=client_ip, user_agent=request.headers.get("user-agent"), order_id=order.id)
    if bio_gate:
        code, msg, data = bio_gate
        return error(code, msg, data)
    scene = "jsapi" if (channel == "wechat" and in_wechat) else "h5"
    if scene == "jsapi" and not user.oa_openid:
        # 不把订单置 expired：order 可能是 N6 复用的既有 pending 单，微信授权未完成只是临时态，
        # 置 expired 会连带作废那张仍可支付/复用的订单（用户完成授权后本可直接续付）。保持 pending，
        # 让用户重新从入口进入后 continue-pay、或再次下单时由 N6 复用；超时由 close_expired_orders 兜底。
        return error(ErrorCode.NOT_LOGIN, "微信授权未完成，请关闭页面重新从入口进入")
    pay_result = await create_payment(
        order_no=order.order_no, amount=amount, subject=product.name,
        client_ip=client_ip, channel=channel, scene=scene, openid=user.oa_openid)
    if not pay_result:
        # 同上：支付平台下单失败多为临时/配置问题，不作废订单（尤其 N6 复用的既有 pending 单）。
        # 保持 pending 并记录失败原因，用户可 continue-pay 重试；超时由 close_expired_orders 兜底关闭。
        order.fail_reason = "支付平台下单失败"
        await db.flush()
        return error(ErrorCode.PAYMENT_FAILED, "支付创建失败，请检查支付配置或稍后重试")
    if pay_result.get("pay_type") == "redirect":
        order.pay_url = pay_result.get("pay_url")
    order.status = "pending"
    order.fail_reason = None   # 复用单可能残留上次下单失败原因，成功拉起支付后清空
    await db.flush()
    return success({
        "order_id": order.id, "order_no": order.order_no, "sku_code": sku,
        "amount": float(amount), "channel": channel, "scene": scene, "pay_params": pay_result,
    })


@router.get("/list")
async def order_list(status: str = Query(None), page: int = Query(1, ge=1),
                     page_size: int = Query(20, ge=1, le=50),
                     db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    query = select(Order).where(Order.user_id == user.id)
    if status:
        query = query.where(Order.status == status)
    total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar() or 0
    items = (await db.execute(
        query.order_by(Order.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    )).scalars().all()
    # M5：批量查询本页订单的 Report，消除 N+1
    order_ids = [i.id for i in items]
    report_map = {}
    if order_ids:
        reps = (await db.execute(select(Report).where(Report.order_id.in_(order_ids)))).scalars().all()
        report_map = {r.order_id: r for r in reps}
    list_data = []
    for item in items:
        # L23：与 POST /order/refund 共用判据。原来这里是白名单式「有报告且未查看」，
        # 与接口的黑名单式条件相反：0 元解读单给出按钮却必然退不掉（见 _self_refund_block）。
        rep = report_map.get(item.id)
        can_refund = _self_refund_block(item, rep) is None
        list_data.append({
            "id": item.id, "order_no": item.order_no, "sku_code": item.sku_code,
            "product_type": item.product_type, "product_name": item.product_name,
            "amount": float(item.amount), "pay_channel": item.pay_channel, "status": item.status,
            "status_text": STATUS_TEXT.get(item.status, item.status), "can_refund": can_refund,
            # L24：能否查看报告由后端单点判定。前端原先只看 product_type in
            # ('single','report')，实时测算单因此拿到了「查看报告」按钮，一点就触发 L21
            # 补生成并白烧付费接口（详见 fulfillment.order_delivers_report）。
            "can_view_report": item.status == "completed" and order_delivers_report(item),
            # 报告是否仍在生成中。生成期间 can_view_report 为假，「查看报告」按钮原先直接
            # 消失，订单页于是没有任何入口可点，用户只能反复退出重进——这是「解读期间
            # 点报告界面没反应」的另一半原因。前端据此把入口换成「生成中，查看进度」。
            "report_generating": bool(rep is not None and rep.status == "generating"
                                      and item.status == "completed"
                                      and order_delivers_report(item)),
            # v19：报告是否已被软删除。仅「解读历史」据此隐藏（财务凭证不受影响，
            # 「我的订单」页仍照常显示）；无 Report 行的订单（会员/实时测算等）恒为 False。
            "report_deleted": bool(rep is not None and rep.deleted_at is not None),
            "created_at": item.created_at.strftime("%Y-%m-%d %H:%M") if item.created_at else None,
        })
    return success({"list": list_data, "total": total, "page": page, "page_size": page_size})


@router.get("/{order_id}")
async def order_detail(order_id: int, db: AsyncSession = Depends(get_db),
                       user: User = Depends(get_current_user)):
    order = (await db.execute(
        select(Order).where(Order.id == order_id, Order.user_id == user.id))).scalar_one_or_none()
    if not order:
        return error(ErrorCode.ORDER_INVALID, "订单不存在")
    report = (await db.execute(select(Report).where(Report.order_id == order.id))).scalar_one_or_none()
    # L23：与 POST /order/refund 共用判据，不再各写一份
    can_refund = _self_refund_block(order, report) is None
    refund_deadline = None
    if can_refund and order.paid_at:
        refund_deadline = (order.paid_at
                           + timedelta(days=settings.REFUND_DAYS)).strftime("%Y-%m-%d %H:%M")
    return success({
        "id": order.id, "order_no": order.order_no, "sku_code": order.sku_code,
        "product_name": order.product_name, "product_type": order.product_type,
        "amount": float(order.amount), "pay_channel": order.pay_channel, "status": order.status,
        "status_text": STATUS_TEXT.get(order.status, order.status),
        "paid_at": order.paid_at.strftime("%Y-%m-%d %H:%M") if order.paid_at else None,
        "can_refund": can_refund, "refund_deadline": refund_deadline,
        # L24：与 /order/list 同一判据，前端不再自行按 product_type 推断
        "can_view_report": order.status == "completed" and order_delivers_report(order),
        "report_generating": bool(report is not None and report.status == "generating"
                              and order.status == "completed"
                              and order_delivers_report(order)),
    })


@router.delete("/{order_id}/report")
async def delete_report(order_id: int, db: AsyncSession = Depends(get_db),
                        user: User = Depends(get_current_user)):
    """v19：删除解读报告（软删）。与档案删除同规则——只从「解读历史」隐藏，
    财务凭证（订单/退款）与已收藏引用均保留；收藏页的 source_alive 会置 False
    打「源已删除」标签，但报告行仍在（reportByOrder 不过滤 deleted_at）故仍可打开。
    无 Report 行的订单（会员/实时测算等交付不走 reports 表）不提供删除。"""
    order = (await db.execute(select(Order).where(
        Order.id == order_id, Order.user_id == user.id))).scalar_one_or_none()
    if not order:
        return error(ErrorCode.ORDER_INVALID, "订单不存在")
    report = (await db.execute(select(Report).where(
        Report.order_id == order_id, Report.user_id == user.id))).scalar_one_or_none()
    if not report:
        return error(ErrorCode.PARAM_ERROR, "该记录无可删除的解读报告")
    if report.deleted_at is None:
        report.deleted_at = datetime.now()
        await db.flush()
    return success(msg="已删除")


# A2：pay-status 主动查单的冷却节流。不复用 common.redis_acquire_lock：那个函数在 Redis 故障时
# 「降级放行」（返回哨兵令牌），语义是宁可多执行一次也不能被锁卡死；这里恰好相反——Redis 挂了
# 就必须停止查单，否则前端 2 秒轮询 × N 个在线用户会直接把支付平台查单接口打到频控
#（微信侧对 out-trade-no 查单限流，超限回 SYSTEM_ERROR，会连带把定时掉单补偿一起弄失效）。
# 查单只是「更快」的补偿路径而非唯一路径：Redis 故障期间 2 分钟一轮的 sync_pending_payments
# 仍会兜底，所以这里可以安心 fail-closed。
async def _acquire_query_cooldown(order_id: int) -> bool:
    """SETNX 冷却窗口：抢到返回 True（本次可以向渠道查单），未抢到或 Redis 故障返回 False。"""
    try:
        ok = await redis_client.set(f"lock:pay_query:{order_id}", "1", nx=True,
                                    ex=settings.PAY_STATUS_QUERY_COOLDOWN)
        return bool(ok)
    except Exception as e:
        logger.warning(f"[支付查单] Redis 异常，本次跳过主动查单（定时任务兜底）"
                       f"order_id={order_id}: {e}")
        return False


@router.get("/{order_id}/pay-status")
async def pay_status(order_id: int, background_tasks: BackgroundTasks,
                     db: AsyncSession = Depends(get_db),
                     user: User = Depends(get_current_user)):
    order = (await db.execute(
        select(Order).where(Order.id == order_id, Order.user_id == user.id))).scalar_one_or_none()
    if not order:
        return error(ErrorCode.ORDER_INVALID, "订单不存在")
    # A2：支付回调可能丢（网络闪断、服务发布重启、平台重试耗尽），此时库里的状态永远不会自己
    # 变好：用户已扣款却看不到开通，只能等 2 分钟后的定时任务。本接口是用户付完款后前端
    # 本来就在轮询的入口，顺手补上主动查单这一层，把「已付款未履约」的收敛时间从分钟级压到秒级。
    # 履约仍走 api.payment._mark_order_paid 同一入口，与回调完全幂等，不会重复发放。
    if (order.status in ("pending", "expired") and order.fulfilled_at is None
            and order.pay_channel in ("wechat", "alipay")
            and order.created_at is not None
            # 给异步回调让路：刚下单就查，渠道大概率还答 NOTPAY，白花一次接口调用
            and order.created_at <= datetime.now() - timedelta(seconds=settings.PAY_QUERY_DELAY_SECONDS)
            and await _acquire_query_cooldown(order.id)):
        try:
            await sync_order_for_user(db, order, background_tasks)
        except Exception as e:
            # 查单失败绝不能让用户连订单状态都看不到：回滚后按库里的状态返回，
            # 下一轮轮询（冷却过后）或定时任务会重试。rollback 是必需的：异常可能发生在
            # SQL 执行中，不回滚会让 session 停在 pending-rollback，后续读库直接报错。
            await db.rollback()
            logger.error(f"[支付查单] pay-status 主动查单异常 order={order.order_no}: {e}")
    return success({"order_id": order.id, "sku_code": order.sku_code, "status": order.status,
                    "status_text": STATUS_TEXT.get(order.status, order.status)})


@router.post("/{order_id}/cancel")
async def cancel_order(order_id: int, db: AsyncSession = Depends(get_db),
                       user: User = Depends(get_current_user)):
    order = (await db.execute(
        select(Order).where(Order.id == order_id, Order.user_id == user.id))).scalar_one_or_none()
    if not order:
        return error(ErrorCode.ORDER_INVALID, "订单不存在")
    if order.status != "pending":
        return error(ErrorCode.ORDER_INVALID, "当前订单状态不可取消")
    await db.execute(update(Order).where(Order.id == order_id, Order.status == "pending")
                     .values(status="cancelled"))
    return success()


@router.post("/{order_id}/continue-pay")
async def continue_pay(order_id: int, request: Request, db: AsyncSession = Depends(get_db),
                       user: User = Depends(get_current_user)):
    """N6：对仍处于 pending 的订单重新拉起支付（复用订单，不重复建单）"""
    # 与 create_order 的 N13、apply_refund 同一护栏：continue-pay 会向支付平台发起 prepay 下单，
    # 无限流时可被脚本高频刷（消耗平台 prepay 配额、放大下单接口成本）。用独立计数键，不与
    # 下单/退款共享额度，避免正常「下单→续付」被相互挤占。
    allowed = await redis_rate_limit(
        redis_client, f"rate:continue_pay:{user.id}", settings.RATE_LIMIT_ORDER_PER_MIN, 60)
    if not allowed:
        return error(ErrorCode.RATE_LIMIT, "操作过于频繁，请稍后再试")
    order = (await db.execute(
        select(Order).where(Order.id == order_id, Order.user_id == user.id))).scalar_one_or_none()
    if not order:
        return error(ErrorCode.ORDER_INVALID, "订单不存在")
    if order.status == "completed":
        return error(ErrorCode.ORDER_INVALID, "订单已支付，无需重复支付")
    if order.status != "pending":
        return error(ErrorCode.ORDER_INVALID, "当前订单状态不可支付，请重新下单")
    # 超时订单直接关闭
    timeout = datetime.now() - timedelta(minutes=settings.ORDER_TIMEOUT_MINUTES)
    if order.created_at < timeout:
        order.status = "expired"
        await db.flush()
        return error(ErrorCode.ORDER_INVALID, "订单已超时，请重新下单")
    ua = (request.headers.get("user-agent") or "").lower()
    in_wechat = "micromessenger" in ua
    channel = order.pay_channel or "wechat"
    if in_wechat and channel == "alipay":
        return error(ErrorCode.PARAM_ERROR, "微信内暂不支持支付宝，请选择微信支付")
    scene = "jsapi" if (channel == "wechat" and in_wechat) else "h5"
    if scene == "jsapi" and not user.oa_openid:
        return error(ErrorCode.NOT_LOGIN, "微信授权未完成，请关闭页面重新从入口进入")
    pay_result = await create_payment(
        order_no=order.order_no, amount=float(order.amount), subject=order.product_name,
        client_ip=get_client_ip(request), channel=channel, scene=scene, openid=user.oa_openid)
    if not pay_result:
        return error(ErrorCode.PAYMENT_FAILED, "支付创建失败，请稍后重试")
    if pay_result.get("pay_type") == "redirect":
        order.pay_url = pay_result.get("pay_url")
    await db.flush()
    return success({"order_id": order.id, "order_no": order.order_no,
                    "sku_code": order.sku_code, "amount": float(order.amount),
                    "pay_params": pay_result})


@router.post("/refund")
async def apply_refund_api(req: RefundRequest, request: Request,
                           db: AsyncSession = Depends(get_db),
                           user: User = Depends(get_current_user)):
    """申请退款（单次解读/双人内容：7天内且未查看）。N2/H4：区分成功/处理中/失败三态

    L22：可退范围必须与 /order/list、/order/{id} 的 can_refund 同一口径。
    交付不由 reports 跟踪的 SKU（NO_REPORT_DELIVERY_SKUS，如实时测算）一律走客服处理。"""
    refund_enabled = await get_bool(db, "refund_enabled", True)
    if not refund_enabled:
        return error(ErrorCode.REFUND_DISABLED, "退款功能暂未开放")
    # 退款会调用支付平台并产生资金变动，必须限流（原本完全无限制，可被脚本高频刷）
    allowed = await redis_rate_limit(
        redis_client, f"rate:refund:{user.id}", settings.RATE_LIMIT_ORDER_PER_MIN, 60)
    if not allowed:
        return error(ErrorCode.RATE_LIMIT, "操作过于频繁，请稍后再试")
    order = (await db.execute(
        select(Order).where(Order.id == req.order_id, Order.user_id == user.id))).scalar_one_or_none()
    if not order:
        return error(ErrorCode.ORDER_INVALID, "订单不存在")
    # H3：已有成功/处理中的退款单则拒绝重复退款
    exist = (await db.execute(select(Refund).where(
        Refund.order_id == order.id,
        Refund.status.in_(["refunded", "processing", "pending_refund"])))).scalars().first()
    if exist:
        return error(ErrorCode.REFUND_NOT_ELIGIBLE, "该订单已在退款流程中，请勿重复申请")
    report = (await db.execute(select(Report).where(Report.order_id == order.id))).scalar_one_or_none()
    # L22/L23：资格判据与两个查询接口的 can_refund 共用 _self_refund_block，
    # 拒绝原因（细化文案）也由它给出，保证「按钮能点 ⟺ 接口放行」恒成立。
    reason = _self_refund_block(order, report)
    if reason:
        return error(ErrorCode.REFUND_NOT_ELIGIBLE, reason)

    # 并发护栏：refunds.order_id 并非唯一约束，上面“SELECT 判重 → INSERT”在无锁下
    # 会被并发穿透（两请求同时通过校验），产生多条退款单并向平台发起多笔退款。
    # 用带状态条件的原子 UPDATE 抢占订单，affected==0 即说明已被其他请求抢占。
    claimed = (await db.execute(
        update(Order).where(Order.id == order.id, Order.status == "completed")
        .values(status="refund_pending"))).rowcount
    if not claimed:
        return error(ErrorCode.REFUND_NOT_ELIGIBLE, "该订单已在退款流程中，请勿重复申请")

    # V-2：退款单号入库即预生成并原样传给平台。此前 apply_refund 内部临时生成——进程在
    # 拿到结果前崩溃会把空单号留在 Refund 行，retry_failed_refunds 重试时会再生成新单号
    # 向平台发起第二笔真实退款；预生成后同一条退款单的任何重试路径复用同一 out_refund_no，
    # 微信/支付宝对重复单号幂等返回已有结果，杜绝“同订单二次真实退款”。
    refund_no = gen_refund_no()
    refund = Refund(order_id=order.id, user_id=user.id, reason=req.reason,
                    description=req.description, status="pending_refund", refund_no=refund_no)
    db.add(refund)
    await db.flush()
    # 【安全审计修复 M6】退款单 + 订单抢占状态必须先持久化、再调渠道。
    # 原实现「CAS 抢占 → 建退款单 → 调渠道（最长 30s）→ 状态落库」全部在
    # 同一事务内、请求结束时才 commit：apply_refund 期间进程崩溃/重启会整体
    # 回滚——若渠道已受理该笔退款，本地却查无记录，用户再次申请会生成新的
    # refund_no 发起第二笔真实退款（微信/支付宝按单号幂等，不同单号=两笔钱）。
    # 先 commit 后，任何崩溃都留下带 refund_no 的 pending_refund 退款单：
    # 判重查询据此拦截二次申请；sync_processing_refunds 主动核实其渠道结论；
    # 若渠道从未受理（404），核实任务将其置 failed 并还原订单，由
    # retry_failed_refunds 复用同一 refund_no 重发——全链路绝不换号。
    await db.commit()
    result = await apply_refund(
        order_no=order.order_no, pay_trade_no=order.pay_trade_no or "",
        amount=float(order.amount), reason=req.reason, channel=order.pay_channel,
        order_amount=float(order.amount), refund_no=refund_no)
    refund.refund_no = result.refund_no or refund_no
    if result.ok:
        refund.status = "refunded"
        order.status = "refunded"
        # M23：回收失败要能感知，不再静默（revoke 内部记录失败日志并返回问题）
        revoke_warn = await revoke_refunded_order(db, order)
        if revoke_warn:
            logger.error(f"退款成功但权益回收异常 order={order.order_no}: {revoke_warn}")
    elif result.status == "processing":
        # H4/N2：退款处理中，订单已由上方抢占置为 refund_pending，等退款回调更新
        refund.status = "processing"
        return success({"status": "processing", "msg": "退款处理中，请留意支付平台通知"})
    else:
        refund.status = "failed"
        refund.fail_reason = result.msg or "支付平台退款接口调用失败"
        # 平台未受理：把抢占时置的 refund_pending 还原为 completed。
        # 必须用 Core UPDATE：ORM 实例内存里的 status 仍是 "completed"，
        # 直接赋值相同值不会生成 UPDATE，库里会错误地停在 refund_pending。
        # retry_failed_refunds 仍会按 Refund.status=='failed' 重试，不影响后续推进。
        # 必须带 status 守卫：从「发起退款被拒」到「执行本行还原」之间，退款回调可能已经
        # 把订单置为 refunded。无守卫的还原会把已退款订单写回 completed——权益不回收、
        # 且可被再次发起退款（重复退款 = 直接资损）。与 scheduler/refund_state 同口径。
        restored = (await db.execute(
            update(Order)
            .where(Order.id == order.id, Order.status == "refund_pending")
            .values(status="completed"))).rowcount
        if not restored:
            logger.error(f"退款失败还原未生效：订单已不在 refund_pending，放弃还原 "
                         f"order={order.order_no} current={order.status}")
        return error(ErrorCode.REFUND_FAILED, "退款申请失败，请稍后重试或联系客服")
    return success()
