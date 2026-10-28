"""管理端卡券接口：目录 / 批量生码 / 批次 / 卡密列表 / 作废 / 导出

接入要点（全部复用本底座既有的管理端安全机制，不再自建一套）：
1) 鉴权复用 admin.require_admin：常量时间比较 + 按 IP 失败计数锁定 +
   审计日志（admin_auth_granted / denied），比独立版「裸比较一个内置默认令牌」强得多。
2) 敏感操作（生码 / 作废 / 查看明文 / 导出）统一走本模块的二次密码校验，
   口径见 _operate_password_error：比 admin._check_operate_password **更严**
   （未配置密码时 fail-closed 直接禁用，而不是放行）。
3) 审计复用 admin._log_operation 写 admin_operation_logs，与全站管理操作同一张台账，
   便于后台「操作日志」页统一检索；不再新建独立的审计表。
4) 全部接口带 Redis 限流：管理令牌一旦泄露，无限流时可在数秒内刷出几十万张卡密并导走。
   读写必须用**不同的 Redis 键**，否则读请求会把写配额吃光（见 _admin_rate_limit）。

========================= 卡券的「资产暴露面」在哪 =========================
生码（产生凭据）与导出/明文查看（拿走凭据）是本模块唯一能造成直接资损的动作，
因此这两类操作都必须过二次密码，且都要留审计。任何「只凭管理令牌就能批量拿到明文卡密」
的路径都是绕过二次密码的后门，本文件里所有返回明文 code 的地方都必须是密码校验之后。
"""
import hashlib
import logging
from datetime import datetime

from fastapi import APIRouter, Depends, Header, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.api.admin import _log_operation, require_admin
from app.core.api.common import ErrorCode, error, get_client_ip, redis_rate_limit, success
from app.core.auth import redis_client
from app.core.database import get_db
from app.core.models import CardBatch, CardCode
from app.core.services import card as card_svc
from app.core.services import credential as credential_svc

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/admin/card", tags=["管理端-卡券"])

# 管理端卡券接口限流：读写分开，正常运营远不会触及
_LIMIT_READ = 120    # 次 / 分 / IP：批次、目录这类普通列表
_LIMIT_WRITE = 20    # 次 / 分 / IP：生码、作废
_LIMIT_EXPORT = 10   # 次 / 分 / IP：导出整批卡密 + 二次密码校验
# 明文卡密单页上限。未通过二次密码时只能看脱敏码，允许大页（用于巡检）；
# 通过密码后按导出等级对待，收紧单页条数，降低一次拖走全批的效率。
_PAGE_SIZE_MASKED = 200
_PAGE_SIZE_PLAIN = 100
_TOKEN_FP_LEN = 16

_STATUS_WHITELIST = (card_svc.CARD_STATUS_UNUSED, card_svc.CARD_STATUS_USED,
                     card_svc.CARD_STATUS_DISABLED,
                     card_svc.CARD_STATUS_DESTROYED)


async def _admin_rate_limit(request: Request, limit: int, scope: str) -> bool:
    """管理端卡券限流。

    键里必须带 scope（read / write / export）：此前读、写共用 `admin:card:{ip}` 一个桶，
    而 redis_rate_limit 是「INCR 计数 + 与传入 limit 比较」的固定窗口，同一个键配不同
    limit 会互相污染 —— 运营在卡密列表里连翻 21 页（读限流允许 120/分），
    计数就到 21，紧接着点「生码」会被判 21 > 20 直接拒绝；反过来写配额也会被读请求提前吃光。
    结果是生码/作废在运营最忙的时候随机失败，且写限流 20/分实际上形同虚设。
    """
    return await redis_rate_limit(
        redis_client, f"admin:card:{scope}:{get_client_ip(request)}", limit, 60)


def _token_fp(token: str) -> str:
    """管理令牌指纹，仅用于审计留痕，绝不落明文令牌。"""
    return hashlib.sha256((token or "").encode("utf-8")).hexdigest()[:_TOKEN_FP_LEN]


async def _operate_password_error(provided: str, db: AsyncSession) -> str:
    """卡券敏感操作的二次密码校验（fail-closed）。返回空串表示通过。

    与 admin._check_operate_password 的**唯一**差异是「未配置密码」时的行为：
      · admin 版本 fail-open（未配置 → 直接放行），因为它服务的是退款、改会员等
        既有管理操作，收紧会连带影响面更大的既有流程；
      · 本函数 fail-closed（未配置 → 直接禁用），因为卡券的生码/明文查看/导出是
        「一次调用就能产生或拿走全部渠道资产」的动作。fail-open 等于给系统留了一条
        「运维忘了配密码 → 任何拿到登录密码的人都能拖走整批卡密」的后门。

    密码源优先读库中 PBKDF2 哈希（控制台可随时修改），未设置时回落 .env；
    校验统一走 credential 的常量时间比较（内部已处理非 ASCII 与空值，不会抛 TypeError）。
    比较时只对「传入值」做 strip（容忍从聊天工具/工单里复制密码带上的首尾空白）。
    """
    if not await credential_svc.operate_password_configured(db):
        return ("未配置操作密码，卡券生码/明文查看/导出已按安全策略禁用，"
                "请在控制台「改密码」或后端环境变量中配置操作密码后重试")
    if not await credential_svc.verify_operate_password(db, (provided or "").strip()):
        return "操作密码错误"
    return ""


class CardGenerateRequest(BaseModel):
    sku_code: str = Field(..., min_length=1, max_length=40)
    count: int = Field(..., ge=1, le=card_svc.BATCH_MAX_COUNT)
    remark: str = Field(None, max_length=200)
    expire_days: int = Field(None, ge=1, le=3650, description="不传=长期有效")
    operate_password: str = Field(None, max_length=100)


class CardDisableRequest(BaseModel):
    operate_password: str = Field(None, max_length=100)


@router.get("/catalog")
async def card_catalog(request: Request,
                       is_admin: bool = Depends(require_admin),
                       db: AsyncSession = Depends(get_db)):
    """可制卡的商品目录（读 products 表，与 H5 售卖口径自动一致）。"""
    if not is_admin:
        return error(ErrorCode.ADMIN_LOCKED, "管理令牌无效或已被锁定")
    if not await _admin_rate_limit(request, _LIMIT_READ, "read"):
        return error(ErrorCode.RATE_LIMIT, "操作过于频繁，请稍后再试")
    return success(await card_svc.card_catalog(db))


@router.post("/generate")
async def card_generate(request: Request,
                        req: CardGenerateRequest,
                        is_admin: bool = Depends(require_admin),
                        x_admin_token: str = Header(default=""),
                        x_operate_password: str = Header(default="", alias="X-Operate-Password"),
                        db: AsyncSession = Depends(get_db)):
    """批量生码（敏感操作，必须通过二次密码）。"""
    if not is_admin:
        return error(ErrorCode.ADMIN_LOCKED, "管理令牌无效或已被锁定")
    if not await _admin_rate_limit(request, _LIMIT_WRITE, "write"):
        return error(ErrorCode.RATE_LIMIT, "操作过于频繁，请稍后再试")
    # 同时接受请求体字段与 X-Operate-Password 请求头：前端两种调用方式都有，
    # 请求头方式不会把密码写进 body 日志/网关审计。
    pwd_err = await _operate_password_error(req.operate_password or x_operate_password, db)
    if pwd_err:
        return error(ErrorCode.NO_PERMISSION, pwd_err)

    try:
        batch = await card_svc.generate_batch(
            db, req.sku_code, req.count,
            created_by=f"admin:{_token_fp(x_admin_token)}",
            remark=req.remark, expire_days=req.expire_days)
        codes = await card_svc.list_batch_codes(db, batch.id)
        await _log_operation(db, request, "card_generate", "card_batch", batch.batch_no,
                             {"sku_code": batch.sku_code, "count": len(codes),
                              "remark": req.remark, "expire_days": req.expire_days,
                              "by": _token_fp(x_admin_token)})
        await db.commit()
    except card_svc.CardRedeemError as e:
        await db.rollback()
        return error(ErrorCode.PARAM_ERROR, e.msg)
    except Exception as e:
        await db.rollback()
        logger.error(f"卡券生码异常: {e}", exc_info=True)
        return error(ErrorCode.PARAM_ERROR, "生码失败，请稍后重试")

    logger.info(f"卡券生码成功 batch={batch.batch_no} sku={batch.sku_code} "
                f"count={len(codes)} by={_token_fp(x_admin_token)}")
    return success({
        "batch_id": batch.id, "batch_no": batch.batch_no, "sku_code": batch.sku_code,
        "count": len(codes), "codes": [c.code for c in codes],
    }, "生码成功")


@router.get("/batch/list")
async def card_batch_list(request: Request,
                          page: int = Query(1, ge=1),
                          page_size: int = Query(20, ge=1, le=100),
                          is_admin: bool = Depends(require_admin),
                          db: AsyncSession = Depends(get_db)):
    if not is_admin:
        return error(ErrorCode.ADMIN_LOCKED, "管理令牌无效或已被锁定")
    if not await _admin_rate_limit(request, _LIMIT_READ, "read"):
        return error(ErrorCode.RATE_LIMIT, "操作过于频繁，请稍后再试")

    total = (await db.execute(select(func.count()).select_from(CardBatch))).scalar() or 0
    rows = (await db.execute(
        select(CardBatch).order_by(CardBatch.id.desc())
        .offset((page - 1) * page_size).limit(page_size))).scalars().all()
    sku_index = await card_svc.load_sku_index(db)
    return success({
        "list": [{
            "id": b.id, "batch_no": b.batch_no, "sku_code": b.sku_code,
            "name": sku_index[b.sku_code].name if b.sku_code in sku_index else b.sku_code,
            "total_count": b.total_count, "used_count": b.used_count,
            "remark": b.remark, "created_by": b.created_by,
            "expire_at": b.expire_at.strftime("%Y-%m-%d %H:%M") if b.expire_at else None,
            "created_at": b.created_at.strftime("%Y-%m-%d %H:%M") if b.created_at else None,
        } for b in rows],
        "total": total, "page": page, "page_size": page_size})


@router.get("/list")
async def card_code_list(request: Request,
                         batch_id: int = Query(None),
                         status_filter: str = Query(None, alias="status"),
                         sku_code: str = Query(None),
                         code: str = Query(None, max_length=64),
                         page: int = Query(1, ge=1),
                         page_size: int = Query(50, ge=1, le=_PAGE_SIZE_MASKED),
                         is_admin: bool = Depends(require_admin),
                         x_admin_token: str = Header(default=""),
                         x_operate_password: str = Header(default="", alias="X-Operate-Password"),
                         db: AsyncSession = Depends(get_db)):
    """卡密列表。**默认只返回脱敏码**；需明文必须通过二次密码。

    【为什么不能默认给明文】
    原实现直接返回 `code` 明文，且只要求管理令牌 —— 于是 `/export`（需要
    X-Operate-Password）的二次密码保护被同一个模块的 `/list` 完全绕过：
    凭证泄露者或越权内部人员只要把 batch_id 翻页拉完（200/页），
    就能把整批未用卡密一模一样地拖走，一次密码都不用输。
    现在默认脱敏，传对 X-Operate-Password 才给明文，并且**明文查看本身写审计**，
    让「谁在什么时候翻了 100 条明文卡密」有据可查。
    """
    if not is_admin:
        return error(ErrorCode.ADMIN_LOCKED, "管理令牌无效或已被锁定")
    if not await _admin_rate_limit(request, _LIMIT_READ, "read"):
        return error(ErrorCode.RATE_LIMIT, "操作过于频繁，请稍后再试")

    # 只要带了密码就按高敏感等级校验：带了但错，直接拒绝，绝不「静默降级成脱敏」——
    # 那样运营会以为看的是明文，拿脱敏码去对客，反而制造客诉。
    plain = False
    if x_operate_password:
        pwd_err = await _operate_password_error(x_operate_password, db)
        if pwd_err:
            return error(ErrorCode.NO_PERMISSION, pwd_err)
        plain = True
        if page_size > _PAGE_SIZE_PLAIN:
            page_size = _PAGE_SIZE_PLAIN
        if not await _admin_rate_limit(request, _LIMIT_EXPORT, "export"):
            return error(ErrorCode.RATE_LIMIT, "明文查看过于频繁，请稍后再试")

    q = select(CardCode)
    if batch_id is not None:
        q = q.where(CardCode.batch_id == batch_id)
    if status_filter:
        if status_filter not in _STATUS_WHITELIST:
            return error(ErrorCode.PARAM_ERROR, "status 取值非法")
        q = q.where(CardCode.status == status_filter)
    if sku_code:
        q = q.where(CardCode.sku_code == sku_code)
    # 按完整兑换码精确定位（控制台「查卡/作废」入口）：复用与兑换链路完全一致的
    # normalize_code 规范化（去分隔符/统一大写/去全角），运营从微信、Excel、工单
    # 里粘贴的任何形态的码都能命中；找不到就返回空列表，不额外暴露信息。
    if code:
        q = q.where(CardCode.code == card_svc.normalize_code(code))

    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar() or 0
    rows = (await db.execute(
        q.order_by(CardCode.id.desc())
        .offset((page - 1) * page_size).limit(page_size))).scalars().all()
    sku_index = await card_svc.load_sku_index(db)

    if plain and rows:
        await _log_operation(db, request, "card_code_view", "card_batch",
                             str(batch_id) if batch_id is not None else "-",
                             {"count": len(rows), "page": page,
                              "by": _token_fp(x_admin_token)})
        await db.commit()
        logger.warning(f"管理端查看明文卡密 count={len(rows)} page={page} "
                       f"by={_token_fp(x_admin_token)} ip={get_client_ip(request)}")

    return success({
        "list": [{
            "id": c.id,
            "code": c.code if plain else None,
            "code_masked": card_svc.mask_code(c.code),
            "sku_code": c.sku_code,
            "name": sku_index[c.sku_code].name if c.sku_code in sku_index else c.sku_code,
            "batch_id": c.batch_id, "status": c.status,
            "used_by": c.used_by, "redeem_order_no": c.redeem_order_no,
            "used_at": c.used_at.strftime("%Y-%m-%d %H:%M") if c.used_at else None,
            "expire_at": c.expire_at.strftime("%Y-%m-%d %H:%M") if c.expire_at else None,
            "created_at": c.created_at.strftime("%Y-%m-%d %H:%M") if c.created_at else None,
        } for c in rows],
        # code_visible 让前端明确知道当前拿到的是明文还是脱敏，避免把脱敏码当明文用。
        "code_visible": plain,
        "total": total, "page": page, "page_size": page_size})


@router.get("/codes/by_batches")
async def card_codes_by_batches(request: Request, ids: str = Query("", max_length=200),
                                x_admin_token: str = Header(default=""),
                                x_operate_password: str = Header(default="", alias="X-Operate-Password"),
                                is_admin: bool = Depends(require_admin),
                                db: AsyncSession = Depends(get_db)):
    """按批次 ID 批量取明文卡密+状态（卡券列表页直接展示卡密用）。

    与 /list 的明文查看同口径：操作密码必输（fail-closed）、导出级限流、写审计；
    区别只是按批批量取，避免列表页一屏几十个批次逐批拉明文触发限流。
    """
    if not is_admin:
        return error(ErrorCode.ADMIN_LOCKED, "管理令牌无效或已被锁定")
    if not await _admin_rate_limit(request, _LIMIT_READ, "read"):
        return error(ErrorCode.RATE_LIMIT, "操作过于频繁，请稍后再试")
    pwd_err = await _operate_password_error(x_operate_password, db)
    if pwd_err:
        return error(ErrorCode.NO_PERMISSION, pwd_err)
    if not await _admin_rate_limit(request, _LIMIT_EXPORT, "export"):
        return error(ErrorCode.RATE_LIMIT, "明文查看过于频繁，请稍后再试")
    try:
        id_list = [int(x) for x in ids.split(",") if x.strip()][:20]
    except ValueError:
        return error(ErrorCode.PARAM_ERROR, "ids 格式非法")
    if not id_list:
        return error(ErrorCode.PARAM_ERROR, "ids 不能为空")
    rows = (await db.execute(
        select(CardCode).where(CardCode.batch_id.in_(id_list))
        .order_by(CardCode.id.asc()))).scalars().all()
    # 护栏：批量取码单次上限 2 万条（20 批 × 满批），防止误操作一次拖走全库卡密；
    # 正常运营一屏的批次量远小于此，超出部分截断并提示分批拉取。
    if len(rows) > 20000:
        rows = rows[:20000]
    if rows:
        await _log_operation(db, request, "card_code_view", "card_batch",
                             ",".join(str(i) for i in id_list),
                             {"count": len(rows), "by": _token_fp(x_admin_token)})
        await db.commit()
    out = {}
    for c in rows:
        out.setdefault(c.batch_id, []).append({"code": c.code, "status": c.status})
    return success({"map": out})


@router.post("/disable/{code_id}")
async def card_disable(code_id: int,
                       request: Request,
                       req: CardDisableRequest = None,
                       is_admin: bool = Depends(require_admin),
                       x_admin_token: str = Header(default=""),
                       x_operate_password: str = Header(default="", alias="X-Operate-Password"),
                       db: AsyncSession = Depends(get_db)):
    """作废一张未使用卡。

    已使用的卡不可作废：卡券单是 0 元权益载体，收回用户已到账的权益需要独立的
    运营流程（而且**不能**走订单退款 —— 退款会触发 revoke_refunded_order，
    用户权益消失而卡券已是 used，两头落空，见 patch 里对退款入口的拦截）。
    """
    if not is_admin:
        return error(ErrorCode.ADMIN_LOCKED, "管理令牌无效或已被锁定")
    if not await _admin_rate_limit(request, _LIMIT_WRITE, "write"):
        return error(ErrorCode.RATE_LIMIT, "操作过于频繁，请稍后再试")
    # 请求体可为空（作废本身不需要业务参数），但二次密码校验要拿到对象，
    # 否则配置了 ADMIN_OPERATE_PASSWORD 时空 body 会因 NoneAttributeError 变 500。
    req = req or CardDisableRequest()
    pwd_err = await _operate_password_error(req.operate_password or x_operate_password, db)
    if pwd_err:
        return error(ErrorCode.NO_PERMISSION, pwd_err)

    try:
        card = await card_svc.disable_code(db, code_id)
        await _log_operation(db, request, "card_disable", "card_code", str(card.id),
                             {"code_masked": card_svc.mask_code(card.code),
                              "sku_code": card.sku_code, "batch_id": card.batch_id,
                              "by": _token_fp(x_admin_token)})
        await db.commit()
    except card_svc.CardRedeemError as e:
        await db.rollback()
        return error(ErrorCode.PARAM_ERROR, e.msg)
    return success({"id": card.id, "status": card.status}, "已作废")


@router.get("/export/{batch_id}")
async def card_export(batch_id: int,
                      request: Request,
                      is_admin: bool = Depends(require_admin),
                      x_admin_token: str = Header(default=""),
                      x_operate_password: str = Header(default="", alias="X-Operate-Password"),
                      db: AsyncSession = Depends(get_db)):
    """导出整批**未使用**卡密：text 为一行一个码，整段复制给外部渠道。

    · 导出是「一次性拿走全部明文卡密」的动作，属最高敏感级别：必须携带二次密码
      （X-Operate-Password 请求头），且使用最严的 _LIMIT_EXPORT 限流。
    · text 只含 unused：原实现把已兑换、已作废的码一起吐给渠道，渠道按清单重复投放，
      用户拿到的码已被用过，凭空产生客诉与退款争议；已兑换的码对交付方也毫无用处。
      已用/已作废的数量仍以计数形式返回，供运营核对批次账目。
    """
    if not is_admin:
        return error(ErrorCode.ADMIN_LOCKED, "管理令牌无效或已被锁定")
    if not await _admin_rate_limit(request, _LIMIT_EXPORT, "export"):
        return error(ErrorCode.RATE_LIMIT, "导出过于频繁，请稍后再试")
    pwd_err = await _operate_password_error(x_operate_password, db)
    if pwd_err:
        return error(ErrorCode.NO_PERMISSION, pwd_err)

    batch = await db.get(CardBatch, batch_id)
    if not batch:
        return error(ErrorCode.PARAM_ERROR, "批次不存在")
    rows = await card_svc.list_batch_codes(db, batch_id)
    # 只看 status=unused 会把「已过期但仍 unused」的卡原样导给渠道，
    # 用户买到后兑换才发现过期，直接变成客诉与退款争议。这里：
    #   1) 过期未用卡不再进入导出清单；
    #   2) 顺手 CAS 置 disabled（WHERE status='unused'，与兑换/作废的并发交错安全），
    #      状态机收敛后它们不可能再被任何路径导出或兑换；
    #   3) 过期数量单独返回并写审计，运营能看出批次里有多少死卡。
    now = datetime.now()
    expired_ids = [r.id for r in rows
                   if r.status == card_svc.CARD_STATUS_UNUSED
                   and r.expire_at and r.expire_at <= now]
    expired_disabled = 0
    if expired_ids:
        res = await db.execute(
            update(CardCode)
            .where(CardCode.id.in_(expired_ids),
                   CardCode.status == card_svc.CARD_STATUS_UNUSED)
            .values(status=card_svc.CARD_STATUS_DISABLED))
        expired_disabled = res.rowcount or 0
    _expired = set(expired_ids)
    unused = [r.code for r in rows
              if r.status == card_svc.CARD_STATUS_UNUSED and r.id not in _expired]
    used_n = sum(1 for r in rows if r.status == card_svc.CARD_STATUS_USED)
    disabled_n = sum(1 for r in rows if r.status == card_svc.CARD_STATUS_DISABLED) + expired_disabled
    await _log_operation(db, request, "card_export", "card_batch", batch.batch_no,
                         {"sku_code": batch.sku_code, "total": len(rows),
                          "unused": len(unused), "used": used_n,
                          "disabled": disabled_n, "expired_disabled": expired_disabled,
                          "by": _token_fp(x_admin_token)})
    await db.commit()
    logger.warning(f"管理端导出卡密 batch={batch.batch_no} unused={len(unused)} "
                   f"by={_token_fp(x_admin_token)} ip={get_client_ip(request)}")
    return success({
        "batch_no": batch.batch_no, "sku_code": batch.sku_code,
        "total": len(rows), "unused_count": len(unused),
        "used_count": used_n, "disabled_count": disabled_n,
        "expired_disabled": expired_disabled,
        "text": "\n".join(unused),
    })
