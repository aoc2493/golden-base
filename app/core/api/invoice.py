"""B1：电子发票 —— 用户端申请入口。

三个设计决定，都与「能不能少写一点」无关，写下来是为了防止后来人当成冗余删掉：

1. 资格判据一律走 services/invoice.order_block，本文件不自作判断。
   /eligible 与 /apply 若各写一份，两份口径迟早走偏，走偏的表现是
   「按钮是亮的、点了报错」或「按钮是灰的、其实能开」，后者等于变相拒开发票。

2. 本路由不做 A6 的「撤回同意即拒绝」校验（archive.py / order.py 都有）。
   这不是漏写：开具发票是《发票管理办法》第十九条的法定义务，属《个保法》
   第十三条第（三）项「为履行法定义务所必需」，其合法性基础不是用户同意。
   若在此处加同意门，就会以「你撤回了同意」为由拒开发票——恰好违法。
   邮箱是发票的唯一交付通道，为履行该义务所必需，仍按最小必要只收这一项。

3. order_id 上有唯一约束，所以 apply 必须捕 IntegrityError。
   先 SELECT 判重再 INSERT，在并发双击下会被穿透（与 order.py 退款抢占同一个坑），
   不捕就是 500，用户看到「服务器错误」而后台已经多了一行。
"""
import logging

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.api.common import ErrorCode, error, redis_rate_limit, success
from app.core.auth import get_current_user, redis_client
from app.config import settings
from app.core.database import get_db
from app.core.models import InvoiceRequest, User
from app.core.schemas import InvoiceApplyRequest
from app.core.services import invoice as invoice_svc

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/invoice", tags=["发票"])


# ==================== 静态文案与资格查询 ====================
# 下面三个端点必须注册在 /{apply_id} 之前：FastAPI 按注册顺序匹配，
# 参数路由先注册会把 /mine 这类字面路径吞掉并回 422（archive.py 的 /all 踩过同一个坑）。

@router.get("/notice")
async def invoice_notice(db: AsyncSession = Depends(get_db)):
    """开票须知与通道开关。刻意不要求登录。

    这是平台对外作出的开票承诺（几天内开、开什么票、超期怎么办），属于应当公示的信息；
    加登录门槛等于把它藏起来，而「用户找不到开票规则」在投诉与检查中与「不提供开票」
    同样被动。返回体全是静态文案与开关位，不含任何用户数据，公开不产生新的泄露面。
    """
    return success(invoice_svc.notice(await invoice_svc.enabled(db)))


@router.get("/eligible")
async def invoice_eligible(order_id: int = Query(..., ge=1),
                           db: AsyncSession = Depends(get_db),
                           user: User = Depends(get_current_user)):
    """该订单能否开票。前端据此决定按钮亮暗与提示文案。

    不可开时把具体原因一并返回，而不是只回一个 false：用户不知道自己该做什么
    （去付款？等退款结果？找客服？）时只会反复点击然后投诉。
    已申请过时带上那条记录的 id，前端可直接跳到详情，不必让他再填一遍表单。
    """
    order = await invoice_svc.ensure_order_owned(db, order_id, user.id)
    inv = await invoice_svc.find_by_order(db, order_id) if order else None
    block = invoice_svc.order_block(order, inv)
    data = {"order_id": order_id, "eligible": block is None}
    if order:
        # 金额与商品名从订单快照回显，前端只用于展示核对，提交时不接受这两个字段
        data["amount"] = float(order.amount) if order.amount is not None else None
        data["product_name"] = order.product_name
        data["order_no"] = order.order_no
    if block:
        data["code"] = block[0]
        data["reason"] = block[1]
    if inv is not None:
        data["existing"] = invoice_svc.brief(inv)
    data["notice"] = invoice_svc.notice(await invoice_svc.enabled(db))
    return success(data)


@router.get("/mine")
async def invoice_mine(status: str = Query("all", description="all/pending/issued/rejected/cancelled"),
                       page: int = Query(1, ge=1),
                       page_size: int = Query(20, ge=1, le=50),
                       db: AsyncSession = Depends(get_db),
                       user: User = Depends(get_current_user)):
    """我的开票记录。邮箱不脱敏：这是用户自己填给自己收票的地址，
    对自己脱敏只会让他怀疑填错了哪一个（后台列表才脱敏，那里看的是别人的信息）。"""
    stmt = select(InvoiceRequest).where(InvoiceRequest.user_id == user.id)
    if status and status != "all":
        stmt = stmt.where(InvoiceRequest.status == status)
    total = (await db.execute(
        select(func.count()).select_from(stmt.subquery()))).scalar() or 0
    rows = (await db.execute(
        stmt.order_by(InvoiceRequest.created_at.desc(), InvoiceRequest.id.desc())
            .offset((page - 1) * page_size).limit(page_size))).scalars().all()
    items = []
    for r in rows:
        d = invoice_svc.brief(r)
        # 可撤销/可重提交位由后端算好再下发，不让前端按 status 自行推断：
        # 状态机以后加一个态，前端漏改就会出现「点了没反应」的按钮。
        d["can_cancel"] = r.status == invoice_svc.ST_PENDING
        d["can_reapply"] = r.status in invoice_svc.REAPPLY_STATUSES
        items.append(d)
    return success({
        "list": items,
        "total": total, "page": page, "page_size": page_size,
        "notice": invoice_svc.notice(await invoice_svc.enabled(db)),
    })


# ==================== 申请与撤销 ====================

@router.post("/apply")
async def invoice_apply(req: InvoiceApplyRequest, request: Request,
                        db: AsyncSession = Depends(get_db),
                        user: User = Depends(get_current_user)):
    """提交开票申请。同一订单被驳回或撤销后重新提交时复用原行（一单一票不松开）。"""
    if not await invoice_svc.enabled(db):
        return error(ErrorCode.INVOICE_DISABLED,
                     invoice_svc.notice(False)["disabled_reason"])
    # 申请会写入台账并触发人工开票，必须限流：无限流时可被脚本灌满台账，
    # 财务面对几千条待开具就无法分辨哪条是真的，等于用垃圾数据把开票通道堵死。
    allowed = await redis_rate_limit(
        redis_client, f"rate:invoice:{user.id}", settings.RATE_LIMIT_ORDER_PER_MIN, 60)
    if not allowed:
        return error(ErrorCode.RATE_LIMIT, "操作过于频繁，请稍后再试")

    order = await invoice_svc.ensure_order_owned(db, req.order_id, user.id)
    inv = await invoice_svc.find_by_order(db, req.order_id) if order else None
    block = invoice_svc.order_block(order, inv)
    if block:
        code, reason = block
        # 已申请过时把那条记录的 id 带回去：前端据此直接跳到详情，
        # 比弹一句「重复提交」有用得多——用户真正想知道的是「那我那张票呢」。
        data = {"existing": invoice_svc.brief(inv)} if (
            code == ErrorCode.INVOICE_DUPLICATED and inv is not None) else None
        return error(code, reason, data)

    msg, norm = invoice_svc.validate_apply(req.invoice_type, req.title, req.tax_no, req.email)
    if msg:
        return error(ErrorCode.PARAM_ERROR, msg)

    item_name = (settings.INVOICE_ITEM_NAME or "").strip()
    remark = (req.remark or "").strip()[:200] or None
    reused = False
    try:
        if inv is not None:
            # 走到这里 inv.status 必然在 REAPPLY_STATUSES 内（order_block 已放行）：
            # 改本行而不是新建行。新建行会撞上 order_id 唯一约束，
            # 而松开约束就会让并发双击真的产生两条申请，进而可能开出两张发票。
            inv.invoice_type = norm["invoice_type"]
            inv.title = norm["title"]
            inv.tax_no = norm["tax_no"] or None
            inv.email = norm["email"]
            inv.remark = remark
            inv.amount = order.amount
            inv.product_name = order.product_name
            inv.item_name = item_name
            inv.status = invoice_svc.ST_PENDING
            inv.reject_reason = None
            inv.handler = None
            inv.invoice_no = None
            inv.invoice_code = None
            inv.issued_at = None
            inv.delivery = None
            inv.invoice_file = None
            inv.need_red_flush = 0
            reused = True
            await db.flush()
        else:
            inv = InvoiceRequest(
                apply_no=invoice_svc.gen_apply_no(), order_id=order.id, order_no=order.order_no,
                user_id=user.id, amount=order.amount, product_name=order.product_name,
                invoice_type=norm["invoice_type"], title=norm["title"],
                tax_no=norm["tax_no"] or None, email=norm["email"], remark=remark,
                item_name=item_name, status=invoice_svc.ST_PENDING, need_red_flush=0)
            db.add(inv)
            await db.flush()
    except IntegrityError:
        # 并发双击：另一个请求已经插入成功，本请求撞唯一约束。
        # 这里必须回滚后按「已申请过」返回，而不是让异常冒成 500——
        # 对用户来说两次点击是同一件事，第二次看到「服务器错误」会以为第一次也失败了，
        # 于是再点第三次，投诉就来了。
        await db.rollback()
        exist = await invoice_svc.find_by_order(db, req.order_id)
        logger.warning(f"[发票] 并发申请被唯一约束拦下 order_id={req.order_id} user={user.id}")
        return error(ErrorCode.INVOICE_DUPLICATED,
                     "该订单已提交开票申请，正在开具中；如需修改抬头请先撤销申请再重新提交",
                     {"existing": invoice_svc.brief(exist)} if exist else None)

    promise = max(int(settings.INVOICE_ISSUE_PROMISE_DAYS or 0), 1)
    logger.info(f"[发票] {'重新提交' if reused else '新增'}开票申请 apply_no={inv.apply_no} "
                f"order={inv.order_no} user={user.id} amount={inv.amount} type={inv.invoice_type}")
    # tip 与 msg 同一句话，写在 data 里而不是只放 msg：前端 request() 只把 json.data 返回给
    # 调用方（msg 在非 0 码时才随错误抛出），不放 data 就拿不到这句带时限的承诺，
    # 只能自己在 JS 里拼一句「3 个工作日」——那就成了前端另抄一份承诺文案。
    tip = f"申请已提交，将在 {promise} 个工作日内开具并发送至您的邮箱"
    return success({"id": inv.id, "apply_no": inv.apply_no, "reused": reused, "tip": tip,
                    "detail": invoice_svc.user_detail(inv)}, msg=tip)


@router.post("/{apply_id}/cancel")
async def invoice_cancel(apply_id: int, request: Request,
                         db: AsyncSession = Depends(get_db),
                         user: User = Depends(get_current_user)):
    """撤销待开具的申请（多为改抬头/改税号）。

    只有 pending 可撤：已开具的发票是已交付的法定凭证，不能由用户单方「取消」，
    必须走红字冲销，而红冲只能在税局系统人工操作——所以这里给出的是客服路径，
    而不是一个点了没反应的按钮。
    """
    inv = (await db.execute(select(InvoiceRequest).where(
        InvoiceRequest.id == apply_id, InvoiceRequest.user_id == user.id))).scalar_one_or_none()
    if not inv:
        # 不区分「不存在」与「不是你的」：后者会泄露申请 id 是否存在的枚举信息
        return error(ErrorCode.NO_PERMISSION, "开票申请不存在")
    if inv.status != invoice_svc.ST_PENDING:
        if inv.status == invoice_svc.ST_ISSUED:
            return error(ErrorCode.INVOICE_NOT_ELIGIBLE,
                         "发票已开具，无法在线撤销；如需修改抬头请联系客服办理红字冲销后重开")
        return error(ErrorCode.INVOICE_NOT_ELIGIBLE,
                     "该申请已结束（已驳回或已撤销），可直接重新提交，无需再撤销")
    inv.status = invoice_svc.ST_CANCELLED
    inv.reject_reason = "用户主动撤销申请"
    inv.handler = None
    await db.flush()
    logger.info(f"[发票] 用户撤销申请 apply_no={inv.apply_no} order={inv.order_no} user={user.id}")
    tip = "已撤销，可修改抬头后重新提交"
    return success({"id": inv.id, "status": inv.status, "tip": tip}, msg=tip)


# ==================== 详情 ====================

@router.get("/{apply_id}")
async def invoice_detail(apply_id: int,
                         db: AsyncSession = Depends(get_db),
                         user: User = Depends(get_current_user)):
    """申请详情。可撤销位由后端算好再下发，不让前端按 status 自行推断：
    状态机以后加一个态，前端漏改就会出现「点了没反应」的按钮。"""
    inv = (await db.execute(select(InvoiceRequest).where(
        InvoiceRequest.id == apply_id, InvoiceRequest.user_id == user.id))).scalar_one_or_none()
    if not inv:
        return error(ErrorCode.NO_PERMISSION, "开票申请不存在")
    d = invoice_svc.user_detail(inv)
    d["can_cancel"] = inv.status == invoice_svc.ST_PENDING
    d["can_reapply"] = inv.status in invoice_svc.REAPPLY_STATUSES
    return success(d)
