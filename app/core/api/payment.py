"""支付路由：支付方式查询 + 微信/支付宝异步回调。

曾有的缺陷（已修复）：本文件早期是占位实现——只把订单置为 completed，既不写
paid_at/pay_trade_no，也不调用 fulfill_paid_order，更没有对接任何支付平台的异步回调路由。
那时「用户付了钱」与「发放会员/权益/计佣」两段完全断开：付款后 membership 仍是非会员、
订单 paid_at=None，且因 pay_trade_no 为空被退款判据（api/order.py 的
_self_refund_block）拦成「无实际支付金额，无需退款」，fulfill_paid_order 从未被调用过。

现为完整闭环，回调入口共用同一个幂等的 _mark_order_paid（成功后调用 fulfill_paid_order）：
  · wechat/notify   —— 微信支付 V3 异步回调（验签解密→履约，含退款回调）；
  · alipay/notify   —— 支付宝异步回调（RSA2 验签→履约）。
主动查单兜底见 services/pay_query.py；回调与查单最终都收口到 _mark_order_paid。
真实回调落地地址由 settings.WECHAT_NOTIFY_URL / ALIPAY_NOTIFY_URL 配置，必须分别指向上面
两个 notify 路由（生产要求 HTTPS，见 main._startup_check 的 N9 项）。
"""
import logging
from datetime import datetime

from fastapi import APIRouter, BackgroundTasks, Depends, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.api.common import success, error, ErrorCode, to_money
from app.core.auth import get_current_user
from app.config import settings
from app.core.database import get_db
from app.core.models import Order, Refund, User
from app.core.services.fulfillment import fulfill_paid_order
from app.core.services.refund_state import apply_channel_refund_status
from app.plugins import registry
from app.core.utils.payment import wechat_pay, alipay
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/payment", tags=["支付"])


class MockPayRequest(BaseModel):
    order_no: str


@router.post("/mock/pay")
async def mock_pay(req: MockPayRequest, background_tasks: BackgroundTasks,
                   db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    """本地演示支付：直接把本人订单标记已付并履约。生产环境一律 403。"""
    if not settings.PAYMENT_MOCK or settings.is_prod_env:
        return error(ErrorCode.NO_PERMISSION, "模拟支付未开启")
    order = (await db.execute(
        select(Order).where(Order.order_no == req.order_no, Order.user_id == user.id)
    )).scalar_one_or_none()
    if not order:
        return error(ErrorCode.PARAM_ERROR, "订单不存在")
    result = await _mark_order_paid(
        db, order, f"MOCK{order.order_no}"[:64], background_tasks, amount_paid=order.amount)
    return success({"order_no": order.order_no, "status": order.status, **result})


@router.get("/methods")
async def list_payment_methods():
    """列出可用的真实支付渠道（微信/支付宝），与 /order/create 的 channel 白名单一致。"""
    methods = []
    if settings.WECHAT_MCH_ID:
        methods.append({"channel": "wechat", "name": "微信支付"})
    if settings.ALIPAY_APP_ID:
        methods.append({"channel": "alipay", "name": "支付宝"})
    return success({"methods": methods})


async def _mark_order_paid(db: AsyncSession, order: Order, pay_trade_no,
                           background_tasks: BackgroundTasks, amount_paid=None) -> dict:
    """统一的「标记已付 → 履约 → 触发报告生成」入口，幂等且并发安全。

    支付平台异步回调会重复投递（微信/支付宝均带重试），前端也可能重复触发确认。
    幂等分两层：① order.fulfilled_at 内存闸拦截「串行重复」（已履约直接返回）；
    ② 带状态条件的原子 UPDATE 抢占「履约权」拦截「并发重复」（见下方 CAS 注释）——
    只靠内存闸时，两条并发回调各自的 session 都会读到 fulfilled_at=None 而双双履约。
    amount_paid 非空时校验回调金额与订单金额一致，防止被篡改金额的伪造回调白送权益。
    本函数只负责状态流转与履约编排；会员/权益/报告/计佣的具体发放全在 fulfill_paid_order 内。
    """
    if order.status == "refunded":
        logger.warning(f"支付回调命中已退款订单，跳过履约 order_no={order.order_no}")
        return {"paid": False, "reason": "refunded"}
    if order.fulfilled_at is not None:
        # 已履约：幂等返回，调用方仍应向平台回 SUCCESS 以停止重试
        return {"paid": True, "fulfilled": False, "idempotent": True}

    if amount_paid is not None and to_money(amount_paid) != to_money(order.amount):
        logger.error(f"支付回调金额与订单不符，拒绝履约 order_no={order.order_no} "
                     f"expect={order.amount} got={amount_paid}")
        return {"paid": False, "reason": "amount_mismatch", "rowcount": 0}

    # 并发护栏：回调可能被并发重复投递（微信/支付宝重试同时到达、用户双击确认）。上面的
    # order.fulfilled_at 内存闸只在「串行重复」下有效——两条回调并发时各自独立的 session 都会
    # 读到 fulfilled_at=None 而双双穿过；随后的 ORM 无条件赋值 status='completed' 又会在对方提交
    # 后重新生效，最终 fulfill_paid_order 执行两次：会员天数二次顺延、重复发放权益
    # （UserEntitlement.order_id 只有普通索引、无唯一约束）、重复计佣流水。与 api/order.py 用户端
    # 退款、scheduler 自动退款同一范式，用带状态条件的原子 UPDATE 抢占「履约权」：只有把订单从
    # 非终态（pending/expired）翻转为 completed 的那条回调 rowcount=1、得以继续履约；并发落败方因
    # WHERE 不再匹配（status 已是 completed）拿到 rowcount=0，直接幂等返回。
    # 抢占条件用 status 的「翻转」而非 fulfilled_at：fulfilled_at 要到 fulfill_paid_order 末尾才写，
    # 抢占瞬间它仍是 NULL，唯有 status 翻动能让落败方 WHERE 失配（MySQL/SQLite 行为一致，不依赖
    # 「同值 UPDATE 是否计入 affected_rows」的方言差异）。expired 仍允许被晚到回调履约（用户在关单
    # 前一刻付款），故排除项只有 completed/refunded。
    now = datetime.now()
    # pay_trade_no 是退款判据（_self_refund_block）与对账的关键，必须落库；截断到列长 String(64)。
    new_trade_no = order.pay_trade_no or (str(pay_trade_no)[:64] if pay_trade_no else None)
    claimed = (await db.execute(
        update(Order)
        .where(Order.id == order.id,
               Order.fulfilled_at.is_(None),
               Order.status.notin_(["completed", "refunded"]))
        .values(status="completed", paid_at=order.paid_at or now, pay_trade_no=new_trade_no)
        .execution_options(synchronize_session=False))).rowcount
    if not claimed:
        # 落败方：另一条回调已抢占并履约（或订单已退款）。刷新到最新状态后幂等返回，
        # 调用方仍应向平台回 SUCCESS 以停止重试。
        await db.refresh(order)
        if order.status == "refunded":
            logger.warning(f"支付回调命中已退款订单，跳过履约 order_no={order.order_no}")
            return {"paid": False, "reason": "refunded", "rowcount": 0}
        return {"paid": True, "fulfilled": False, "idempotent": True, "rowcount": 0}
    # 抢占成功：刷新 ORM 实例以携带 CAS 写入的 status/paid_at/pay_trade_no，再交给 fulfill_paid_order
    # （它内部仍以 fulfilled_at 兜底，此刻仍为 NULL，正常履约）。
    await db.refresh(order)

    result = await fulfill_paid_order(db, order)
    if result.get("need_report_task"):
        # 后台生成任务经插件钩子调度（core 不直接 import 具体插件任务）；
        # 失败由失败报告自动退款兜底，不阻塞回调。
        _entry, _ = registry.cap_by_sku(order.sku_code)
        _gen = _entry.service.generation_task() if _entry else None
        if _gen:
            background_tasks.add_task(_gen, order.id)
    await db.flush()
    logger.info(f"订单已支付并完成履约 order_no={order.order_no} sku={order.sku_code} "
                f"need_report_task={result.get('need_report_task')}")
    return {"paid": True, "fulfilled": result.get("fulfilled"),
            "need_report_task": result.get("need_report_task"), "rowcount": 1}


@router.post("/wechat/notify")
async def wechat_notify(request: Request, background_tasks: BackgroundTasks,
                        db: AsyncSession = Depends(get_db)):
    """微信支付 V3 异步回调（无用户态，由微信服务器调用，安全性由平台证书验签保证）。
    微信约定：处理成功回 HTTP 200 + {"code":"SUCCESS"}；失败回 HTTP 4xx/5xx + {"code":"FAIL"}
    触发重试。verify_callback 内部完成时间戳防重放 + 平台证书验签 + APIv3 密钥解密，
    未配 WECHAT_PLATFORM_CERT_PATH 时一律拒收（见 utils/payment.py）。
    幂等/并发：验签后经条件 UPDATE 抢履约权，WHERE status 为非终态才翻转，
    rowcount=1 才履约、并发落败方幂等回执（见 _mark_order_paid）。"""
    # 【安全审计 L1 + M2：DoS 加固】验签前的报文体硬上限。微信回调明文不足 10KB，64KB 已是十余倍冗余。
    # M2：先按 Content-Length 预检——原实现 await request.body() 把整个 body 读进内存后才判大小，
    # 攻击者发一个全局上限（8MB）以内、但远超 64KB 的 body 就能让回调白白缓冲整包再拒绝；预检超限
    # 直接 413，一个字节都不读。chunked 无 Content-Length 时由下方 len(body) 兜底（全局流式中间件已限 8MB）。
    _cl = request.headers.get("content-length")
    if _cl and _cl.isdigit() and int(_cl) > 64 * 1024:
        logger.warning(f"微信回调 Content-Length 超限已拒绝 cl={_cl}")
        return JSONResponse(status_code=413, content={"code": "FAIL", "message": "报文过大"})
    body = await request.body()
    if len(body) > 64 * 1024:
        logger.warning(f"微信回调报文过大已拒绝 size={len(body)}")
        return JSONResponse(status_code=413, content={"code": "FAIL", "message": "报文过大"})
    headers = {k.lower(): v for k, v in request.headers.items()}
    # 前置判定「凭据是否配好」。未配置时 verify_callback 一律返回 None，与「签名被篡改」
    # 无法区分：上游只看到 400、日志只有一条 WARNING，运维极易把「环境没配凭证」
    # 误判成「正在被攻击」。故显式回 503 + ERROR（走 B2 告警通道），把两者分开。
    if not wechat_pay.can_verify_callback():
        logger.error("微信支付回调被拒绝：商户参数/验签凭据未配置完整，无法验签"
                     "（需 WECHAT_MCH_ID + WECHAT_API_V3_KEY，"
                     "且 WECHAT_PLATFORM_CERT_PATH / WECHAT_PUBLIC_KEY_PATH 二者之一）")
        return JSONResponse(status_code=503, content={"code": "FAIL", "message": "支付未配置"})
    verify_callback = wechat_pay.verify_callback
    result = verify_callback(headers, body)
    if not result:
        logger.warning("微信支付回调验签/解密失败，已拒绝")
        return JSONResponse(status_code=400, content={"code": "FAIL", "message": "验证失败"})

    if result.get("event") == "refund":
        ok = await _handle_wechat_refund(db, result)
        return JSONResponse(status_code=200 if ok else 500,
                            content={"code": "SUCCESS" if ok else "FAIL",
                                     "message": "成功" if ok else "处理失败"})

    # event == "payment"
    if result.get("status") != "SUCCESS":
        # 非成功交易态（NOTPAY/PAYERROR/CLOSED 等）：不履约，回 SUCCESS 停止无谓重试
        logger.info(f"微信回调非成功交易态 order_no={result.get('order_no')} status={result.get('status')}")
        return JSONResponse(status_code=200, content={"code": "SUCCESS", "message": "成功"})
    order = (await db.execute(
        select(Order).where(Order.order_no == result.get("order_no")))).scalar_one_or_none()
    if not order:
        logger.error(f"微信回调订单不存在 order_no={result.get('order_no')}")
        return JSONResponse(status_code=404, content={"code": "FAIL", "message": "订单不存在"})
    r = await _mark_order_paid(db, order, result.get("pay_trade_no"),
                               background_tasks, amount_paid=result.get("amount"))
    if r.get("reason") == "amount_mismatch":
        return JSONResponse(status_code=400, content={"code": "FAIL", "message": "金额不符"})
    if not r.get("rowcount", 1):
        # 条件更新抢履约权落败（并发重复回调）：另一回调已履约，幂等回执
        logger.info(f"微信回调幂等命中，已由另一回调履约 order_no={result.get('order_no')}")
    return JSONResponse(status_code=200, content={"code": "SUCCESS", "message": "成功"})


async def _handle_wechat_refund(db: AsyncSession, result: dict) -> bool:
    """微信退款回调（H2/H4）：据 refund_status 更新退款单与订单，成功则回收权益/冲佣。
    对应 api/order.py 中退款返回 processing 的分支——那里把订单置为 refund_pending 后，
    正是等本回调给出最终结论（SUCCESS/CLOSED/ABNORMAL）。返回 False 让微信重试。

    状态迁移交给 services/refund_state.apply_channel_refund_status：后台「同步渠道状态」
    与定时主动查退款走的是同一个函数，保证「回调到了」与「我们去查了」结论完全一致；
    否则两条链路对同一个渠道状态各写一份迁移，迟早口径分裂。
    """
    refund_no = result.get("refund_no")
    refund_status = result.get("refund_status")  # SUCCESS / PROCESSING / CLOSED / ABNORMAL
    # refunds.order_id 无唯一约束、refund_no 亦可能重复投递，用 scalars().first() 防多行异常
    refund = (await db.execute(
        select(Refund).where(Refund.refund_no == refund_no))).scalars().first()
    if not refund:
        logger.error(f"微信退款回调：退款单不存在 refund_no={refund_no}")
        return False
    # 金额校验：退款回调此前只按 refund_status 迁状态，不核对退款金额——
    # 金额被篡改或渠道多退时本地会静默接受。此处以本地退款单金额为准，
    # 不符即拒绝迁移并留痕（FAIL-CLOSED），由人工/对账介入。
    cb_amount = result.get("amount")
    local_amount = getattr(refund, "amount", None)
    if cb_amount is not None and local_amount is not None:
        try:
            if to_money(cb_amount) != to_money(local_amount):
                logger.error(f"微信退款回调金额与本地退款单不符，拒绝状态迁移 "
                             f"refund_no={refund_no} local={local_amount} channel={cb_amount}")
                return False
        except Exception as _e:
            logger.error(f"退款回调金额比对异常（按不符处理）refund_no={refund_no}: {_e}")
            return False
    await apply_channel_refund_status(db, refund, refund_status, source="wechat_callback")
    return True


@router.post("/alipay/notify")
async def alipay_notify(request: Request, background_tasks: BackgroundTasks,
                        db: AsyncSession = Depends(get_db)):
    """支付宝异步回调（无用户态，由支付宝服务器调用，安全性由 RSA2 验签保证）。
    支付宝约定：处理成功返回纯文本 "success"；否则返回 "failure"（HTTP 200）触发重试。
    支付宝退款为同步返回（apply_refund 内 api_alipay_trade_refund 立即得结果），无需退款回调。
    幂等/并发：验签后经条件 UPDATE 抢履约权，WHERE status 为非终态才翻转，
    rowcount=1 才履约、并发落败方幂等回执（见 _mark_order_paid）。"""
    # 【安全审计 L1 + M2：DoS 加固】同微信侧：支付宝回调为表单提交，正常不足 16KB，64KB 硬上限。
    # M2：先按 Content-Length 预检，超限直接 413 不读 body（理由同微信侧）；chunked 由 len(body) 兜底。
    _cl = request.headers.get("content-length")
    if _cl and _cl.isdigit() and int(_cl) > 64 * 1024:
        logger.warning(f"支付宝回调 Content-Length 超限已拒绝 cl={_cl}")
        return PlainTextResponse("failure", status_code=413)
    body = await request.body()
    if len(body) > 64 * 1024:
        logger.warning(f"支付宝回调报文过大已拒绝 size={len(body)}")
        return PlainTextResponse("failure", status_code=413)
    form = await request.form()
    form_data = {k: v for k, v in form.items()}
    # 同微信侧：未配置时 verify_callback 恒返回 None，与验签失败不可区分，
    # 显式回 503 + ERROR，便于运维区分「没配凭证」与「验签失败」。
    if not alipay.is_configured():
        logger.error("支付宝回调被拒绝：支付宝商户/密钥未配置完整，无法验签")
        return PlainTextResponse("failure", status_code=503)
    verify_callback = alipay.verify_callback
    result = verify_callback(form_data)
    if not result:
        logger.warning("支付宝回调验签失败，已拒绝")
        return PlainTextResponse("failure")
    if result.get("event") == "ignore":
        # 非终态（WAIT_BUYER_PAY 等）：验签通过但不处理，回 success 停止重试
        return PlainTextResponse("success")
    order = (await db.execute(
        select(Order).where(Order.order_no == result.get("order_no")))).scalar_one_or_none()
    if not order:
        logger.error(f"支付宝回调订单不存在 order_no={result.get('order_no')}")
        return PlainTextResponse("failure")
    r = await _mark_order_paid(db, order, result.get("pay_trade_no"),
                               background_tasks, amount_paid=result.get("amount"))
    if r.get("reason") == "amount_mismatch":
        return PlainTextResponse("failure")
    if not r.get("rowcount", 1):
        # 条件更新抢履约权落败（并发重复回调）：幂等回执
        logger.info(f"支付宝回调幂等命中 order_no={result.get('order_no')}")
    return PlainTextResponse("success")
