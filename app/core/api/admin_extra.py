"""管理端全量数据映射：把此前只在库里、后台看不到的数据全部暴露给运营后台。

背景：管理后台是站内最高权限入口，运营者需要看到系统全部数据：
- 审计日志 admin_operation_logs（此前只写不读，118 条沉在库里）
- 合规留痕 compliance_consents、AI 生成留痕 ai_generation_logs（留存表）
- 用户反馈 feedbacks（H5 有提交入口，后台无查看界面，反馈石沉大海）
- 系统配置 system_configs（改公告/开关只能直接改库）
- 归因触达 attribution_touches、会员流水 membership_ledger、
  验证付费台账 verified_paid_users、考试记录 exam_records、
  违规记录 violation_records（全量，不限单个推广员）、月度业绩 monthly_performances
- 用户详情补齐：插件业务数据（经注册表聚合）、权益明细 user_entitlements

写操作仅两个（反馈处理 / 配置修改），复用 require_admin 门禁（令牌+锁定+IP白名单），
配置修改另要求操作密码并落审计日志，与 admin.py 敏感操作口径一致。
"""
import json
from datetime import datetime
from decimal import Decimal
from types import SimpleNamespace

from fastapi import APIRouter, Body, Depends, Query, Request
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.api.common import success, error, ErrorCode, get_client_ip
from app.plugins import registry
from app.core.api.admin import require_admin, _check_operate_password, _like_escape, _admin_router_rate_limit
from app.core.services import credential as credential_svc
from app.core.models import (
    AdminOperationLog, ComplianceConsent, Feedback, SystemConfig,
    AiGenerationLog, AttributionTouch, MembershipLedger, VerifiedPaidUser,
    ExamRecord, ViolationRecord, MonthlyPerformance, UserEntitlement,
    Report, CommissionFailLog,
)

# router 级限流（与 admin.py 同口径，见其 _admin_router_rate_limit 注释）
router = APIRouter(prefix="/admin", tags=["管理端-全量数据"],
                   dependencies=[Depends(_admin_router_rate_limit)])


# ---------- 工具 ----------
def _dump(row, fields):
    out = {}
    for f in fields:
        v = getattr(row, f, None)
        if isinstance(v, datetime):
            v = v.strftime("%Y-%m-%d %H:%M:%S")
        elif isinstance(v, Decimal):
            v = float(v)
        out[f] = v
    return out


async def _paged(db, model, fields, page, page_size, filters=None, order_col=None):
    page = max(1, page)
    page_size = min(max(1, page_size), 100)
    q = select(model)
    cq = select(func.count(model.id))
    if filters:
        for f in filters:
            q = q.where(f)
            cq = cq.where(f)
    total = (await db.execute(cq)).scalar() or 0
    q = q.order_by((order_col if order_col is not None else model.id).desc())
    q = q.offset((page - 1) * page_size).limit(page_size)
    rows = (await db.execute(q)).scalars().all()
    return {"list": [_dump(r, fields) for r in rows],
            "total": total, "page": page, "page_size": page_size}


async def _audit(db, request, action, target_type=None, target_id=None, detail=None):
    try:
        db.add(AdminOperationLog(
            action=action, target_type=target_type,
            target_id=str(target_id) if target_id is not None else None,
            detail=detail if isinstance(detail, str) else (
                json.dumps(detail, ensure_ascii=False, default=str) if detail else None),
            ip=get_client_ip(request)))
        await db.commit()
    except Exception:
        await db.rollback()


def _deny(is_admin):
    if not is_admin:
        return error(ErrorCode.ADMIN_LOCKED, "管理令牌无效或已被锁定")
    return None


# ---------- 审计日志（此前只写不读） ----------
@router.get("/audit-logs")
async def admin_audit_logs(page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100),
                           action: str = Query("", max_length=60),
                           db: AsyncSession = Depends(get_db),
                           is_admin: bool = Depends(require_admin)):
    err = _deny(is_admin)
    if err:
        return err
    filters = [AdminOperationLog.action.like(f"%{_like_escape(action)}%", escape="\\")] if action else None
    return success(await _paged(db, AdminOperationLog,
                                ["id", "action", "target_type", "target_id", "detail", "ip", "created_at"],
                                page, page_size, filters))


# ---------- 合规同意留痕 ----------
@router.get("/consents")
async def admin_consents(page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100),
                         user_id: int = Query(None),
                         db: AsyncSession = Depends(get_db),
                         is_admin: bool = Depends(require_admin)):
    err = _deny(is_admin)
    if err:
        return err
    filters = [ComplianceConsent.user_id == user_id] if user_id else None
    return success(await _paged(db, ComplianceConsent,
                                ["id", "user_id", "distributor_id", "doc_type", "doc_version",
                                 "agreed", "order_id", "ip", "user_agent", "agreed_at"],
                                page, page_size, filters))


# ---------- 用户反馈（H5 可提交，后台首次可看可处理） ----------
@router.get("/feedbacks")
async def admin_feedbacks(page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100),
                          status: str = Query("", max_length=20),
                          db: AsyncSession = Depends(get_db),
                          is_admin: bool = Depends(require_admin)):
    err = _deny(is_admin)
    if err:
        return err
    filters = [Feedback.status == status] if status else None
    return success(await _paged(db, Feedback,
                                ["id", "user_id", "type", "content", "images", "status", "created_at"],
                                page, page_size, filters))


@router.post("/feedbacks/{feedback_id}/resolve")
async def admin_feedback_resolve(feedback_id: int, request: Request,
                                 payload: dict = Body(...),
                                 db: AsyncSession = Depends(get_db),
                                 is_admin: bool = Depends(require_admin)):
    err = _deny(is_admin)
    if err:
        return err
    status = payload.get("status")
    if status not in ("pending", "resolved", "rejected"):
        return error(ErrorCode.PARAM_ERROR, "status 仅支持 pending/resolved/rejected")
    row = (await db.execute(select(Feedback).where(Feedback.id == feedback_id))).scalar_one_or_none()
    if not row:
        return error(ErrorCode.PARAM_ERROR, "反馈不存在")
    old = row.status
    row.status = status
    await db.commit()
    await _audit(db, request, "feedback_resolve", "feedback", feedback_id,
                 {"old": old, "new": status})
    return success(msg="反馈状态已更新")


# ---------- 系统配置（首次可在后台查看与修改） ----------
@router.get("/configs")
async def admin_configs(db: AsyncSession = Depends(get_db),
                        is_admin: bool = Depends(require_admin)):
    err = _deny(is_admin)
    if err:
        return err
    rows = (await db.execute(select(SystemConfig).order_by(SystemConfig.config_key.asc()))).scalars().all()
    # 密码哈希保留键绝不外曝：/configs 是运营调参面板，若把 PBKDF2 哈希列出来，
    # 等于把离线爆破素材交给任何能进后台的人；这里一律过滤掉。
    rows = [r for r in rows if r.config_key not in credential_svc.RESERVED_KEYS]
    return success({"list": [{"key": r.config_key, "value": r.config_value,
                              "updated_at": r.updated_at.strftime("%Y-%m-%d %H:%M:%S") if r.updated_at else None}
                             for r in rows]})


# 可写配置键白名单：system_configs 的消费方全仓枚举
# （config_helper 的 get_config/get_bool/get_float/get_int 全部调用点
#  + main.py 初始化种子 + system.py 公开配置白名单 _PUBLIC_KEYS）。
# 原实现允许创建任意 ≤50 字符的新键——当前虽无敏感消费方，但「管理令牌即全量写」
# 的敞开面意味着未来任何新增安全相关键（开关/费率/阈值）都会即刻暴露在
# 本接口下且无人 review。白名单外的新键一律拒绝；新增配置项必须先在此登记。
_CONFIG_WRITABLE_KEYS = {
    # 业务开关（get_bool）
    "paid_reports_enabled", "refund_enabled", "distribution_enabled", "invoice_enabled",
    # 运营文案/展示（system.py _PUBLIC_KEYS 中的可写项）
    "announcement", "vip_benefits", "theme", "result_cache_days",
    # 规则文本与版本号（仅影响展示文案，费率仍在 .env/settings，见 distribution.py L1060）
    "membership_rules", "membership_rule_version",
    "distribution_rules", "distribution_rule_version",
    # 分销运营参数（get_float/get_int）
    "withdraw_min", "withdraw_daily_limit", "commission_settle_days",
}


@router.post("/configs/update")
async def admin_config_update(request: Request,
                              payload: dict = Body(...),
                              db: AsyncSession = Depends(get_db),
                              is_admin: bool = Depends(require_admin)):
    err = _deny(is_admin)
    if err:
        return err
    key = str(payload.get("key") or "").strip()
    if not key or len(key) > 50:
        return error(ErrorCode.PARAM_ERROR, "配置键不能为空且不超过 50 字符")
    # 保留键禁写：防止借道配置接口覆写密码哈希（那将绕过改密端点的双因子重认证与强度校验）
    if key in credential_svc.RESERVED_KEYS:
        return error(ErrorCode.PARAM_ERROR, "该配置项为系统保留（密码哈希），请通过「改密码」入口变更")
    # 白名单校验：拒绝创建白名单外的新键（含改写未知旧键——未知键同样无消费方）
    if key not in _CONFIG_WRITABLE_KEYS:
        return error(ErrorCode.PARAM_ERROR,
                     "该配置键不在可写白名单内；新增配置项需在后端 _CONFIG_WRITABLE_KEYS 登记后再开放")
    # value 收敛为非空字符串且 ≤2000 字符——原实现任意 JSON 都照单写入，
    # 一条大对象/数字/嵌套结构会让消费方按 str 读值时行为不可预期。
    value = payload.get("value")
    if value is None or not isinstance(value, str) or not value.strip():
        return error(ErrorCode.PARAM_ERROR, "配置值必须为非空字符串")
    if len(value) > 2000:
        return error(ErrorCode.PARAM_ERROR, "配置值不能超过 2000 字符")
    pw_err = await _check_operate_password(SimpleNamespace(operate_password=payload.get("operate_password")), db)
    if pw_err:
        return error(ErrorCode.NO_PERMISSION, pw_err)
    row = (await db.execute(select(SystemConfig).where(SystemConfig.config_key == key))).scalar_one_or_none()
    old = row.config_value if row else None
    if row:
        row.config_value = value
    else:
        db.add(SystemConfig(config_key=key, config_value=value))
    await db.commit()
    await _audit(db, request, "system_config_update", "system_config", key,
                 {"old": old, "new": value})
    return success({"key": key}, msg="配置已保存")


# ---------- AI 生成留痕 ----------
@router.get("/ai-logs")
async def admin_ai_logs(page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100),
                        user_id: int = Query(None),
                        db: AsyncSession = Depends(get_db),
                        is_admin: bool = Depends(require_admin)):
    err = _deny(is_admin)
    if err:
        return err
    filters = [AiGenerationLog.user_id == user_id] if user_id else None
    return success(await _paged(db, AiGenerationLog,
                                ["id", "content_id", "user_id", "order_id", "report_id", "scene",
                                 "ai", "provider", "model", "prompt_digest",
                                 "input_chars", "output_chars", "created_at"],
                                page, page_size, filters))


# ---------- 归因触达 ----------
@router.get("/attribution")
async def admin_attribution(page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100),
                            distributor_id: int = Query(None),
                            db: AsyncSession = Depends(get_db),
                            is_admin: bool = Depends(require_admin)):
    err = _deny(is_admin)
    if err:
        return err
    filters = [AttributionTouch.distributor_id == distributor_id] if distributor_id else None
    return success(await _paged(db, AttributionTouch,
                                ["id", "visitor_key", "invite_code", "distributor_id", "ip",
                                 "user_agent", "touched_at", "bound_user_id"],
                                page, page_size, filters))


# ---------- 会员流水（发放/回滚） ----------
@router.get("/membership-ledger")
async def admin_membership_ledger(page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100),
                                  user_id: int = Query(None),
                                  db: AsyncSession = Depends(get_db),
                                  is_admin: bool = Depends(require_admin)):
    err = _deny(is_admin)
    if err:
        return err
    filters = [MembershipLedger.user_id == user_id] if user_id else None
    return success(await _paged(db, MembershipLedger,
                                ["id", "user_id", "order_id", "order_no", "level",
                                 "grant_days", "action", "created_at"],
                                page, page_size, filters))


# ---------- 验证付费台账 ----------
@router.get("/verified-paid")
async def admin_verified_paid(page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100),
                              distributor_id: int = Query(None),
                              db: AsyncSession = Depends(get_db),
                              is_admin: bool = Depends(require_admin)):
    err = _deny(is_admin)
    if err:
        return err
    filters = [VerifiedPaidUser.distributor_id == distributor_id] if distributor_id else None
    return success(await _paged(db, VerifiedPaidUser,
                                ["id", "distributor_id", "buyer_id", "first_order_id",
                                 "first_paid_at", "verify_at", "status", "created_at", "updated_at"],
                                page, page_size, filters))


# ---------- 考试记录 ----------
@router.get("/exam-records")
async def admin_exam_records(page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100),
                             user_id: int = Query(None),
                             db: AsyncSession = Depends(get_db),
                             is_admin: bool = Depends(require_admin)):
    err = _deny(is_admin)
    if err:
        return err
    filters = [ExamRecord.user_id == user_id] if user_id else None
    return success(await _paged(db, ExamRecord,
                                ["id", "user_id", "distributor_id", "score", "passed",
                                 "attempt_no", "created_at"],
                                page, page_size, filters))


# ---------- 违规记录（全量；单推广员视角 admin.py 已有 /distributors/{id}/violations） ----------
@router.get("/violations")
async def admin_violations(page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100),
                           distributor_id: int = Query(None), level: str = Query("", max_length=12),
                           db: AsyncSession = Depends(get_db),
                           is_admin: bool = Depends(require_admin)):
    err = _deny(is_admin)
    if err:
        return err
    filters = []
    if distributor_id:
        filters.append(ViolationRecord.distributor_id == distributor_id)
    if level:
        filters.append(ViolationRecord.level == level)
    return success(await _paged(db, ViolationRecord,
                                ["id", "distributor_id", "user_id", "level", "action", "reason",
                                 "order_id", "report_ticket_id", "frozen_until", "clawback_amount",
                                 "handler", "status", "created_at"],
                                page, page_size, filters or None))


# ---------- 月度业绩 ----------
@router.get("/performances")
async def admin_performances(page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100),
                             distributor_id: int = Query(None),
                             db: AsyncSession = Depends(get_db),
                             is_admin: bool = Depends(require_admin)):
    err = _deny(is_admin)
    if err:
        return err
    filters = [MonthlyPerformance.distributor_id == distributor_id] if distributor_id else None
    return success(await _paged(db, MonthlyPerformance,
                                ["id", "distributor_id", "month", "total_amount", "ladder_uplift",
                                 "ladder_adjust", "final_rank", "rank_reward", "clawback",
                                 "disqualified", "settled", "settled_at", "created_at", "updated_at"],
                                page, page_size, filters, order_col=MonthlyPerformance.month))


# ---------- 计佣失败记录（abandoned=佣金永久丢失，需人工介入；此前后台零可见） ----------
@router.get("/commission-fails")
async def admin_commission_fails(page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100),
                                 status: str = Query("", max_length=20),
                                 db: AsyncSession = Depends(get_db),
                                 is_admin: bool = Depends(require_admin)):
    """计佣失败记录。status pending/success/abandoned；abandoned 是重试放弃、
    佣金永久未入账的盲区，运营必须能看到并人工补账，否则与该表「避免佣金静默丢失」初衷相惖。"""
    err = _deny(is_admin)
    if err:
        return err
    filters = [CommissionFailLog.status == status] if status else None
    return success(await _paged(db, CommissionFailLog,
                                ["id", "order_id", "order_no", "fail_reason", "retry_count",
                                 "status", "created_at", "updated_at"],
                                page, page_size, filters))


# ---------- 命书报告（reports：一单一报告；failed=已付费未交付，关键运营事故） ----------
@router.get("/report-docs")
async def admin_report_docs(page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100),
                            status: str = Query("", max_length=20),
                            db: AsyncSession = Depends(get_db),
                            is_admin: bool = Depends(require_admin)):
    """命书报告状态台账。status generating/completed/failed/refunded；failed 表示用户
    已付费但命书未生成成功，需人工重跑或退款——此前 admin 端对 reports 表零可见。
    列表不返回 chapters/ai_meta 大 JSON 字段，避免单次查询拉回海量正文。
    deleted_at 一并返回——refunded 行的该列即「退款软销毁」时间（用户端
    「解读历史」「我的收藏」全部入口不可达，正文仍留在库内可复原）；completed
    行非空则是用户自助删除。"""
    err = _deny(is_admin)
    if err:
        return err
    filters = [Report.status == status] if status else None
    return success(await _paged(db, Report,
                                ["id", "order_id", "user_id", "title", "status",
                                 "retry_count", "viewed_at", "deleted_at",
                                 "created_at", "updated_at"],
                                page, page_size, filters))


# ---------- 用户详情补齐：插件业务数据 + 权益明细 ----------
@router.get("/users/{user_id}/extra")
async def admin_user_extra(user_id: int,
                           db: AsyncSession = Depends(get_db),
                           is_admin: bool = Depends(require_admin)):
    err = _deny(is_admin)
    if err:
        return err
    ents = (await db.execute(
        select(UserEntitlement).where(UserEntitlement.user_id == user_id)
        .order_by(UserEntitlement.id.desc()).limit(50))).scalars().all()
    # 插件专属业务数据（如业务档案）经注册表聚合；core 只放通用 entitlements
    data = {"entitlements": [_dump(t, ["id", "sku_code", "feature", "status", "order_id",
                                       "biz_key", "expire_at", "created_at"])
                             for t in ents]}
    data.update(await registry.admin_user_extra_data(user_id, db))
    return success(data)
