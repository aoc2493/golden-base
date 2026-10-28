"""分销路由：推广中心（状态/佣金/提现/团队/规则）。

前端 Api 调用面与后端路由此前完全脱节（前端调 /status|commissions|withdrawals|
withdraw|team|rules，后端只有无人调用的 /info），推广中心/提现/佣金/团队/规则
五个页面全部 404/数据加载失败。服务层（services/distribution.py）已完整，
本文件按前端契约全部接线。
"""
import logging
import re
from datetime import datetime

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.api.common import success, error, ErrorCode, get_client_ip, redis_rate_limit
from app.core.auth import get_current_user, redis_client
from app.config import settings
from app.core.database import get_db
from app.core.models import User, Order, CommissionLog, Withdrawal
from app.core.schemas import TouchRequest, WithdrawRequest
from app.core.services import distribution as dist_svc
from app.core.services.config_helper import get_bool, get_float, get_config
from app.core.services.distribution import ensure_distributor, apply_withdrawal, build_distribution_rules, promotion_progress, DISTRIBUTION_RULE_LABELS
from app.core.services.distribution_rank import get_top_ranking, get_my_month, rank_pool_cap
from app.core.services import consent as consent_svc
# A6：库里的收款账号是密文，脱敏前必须先解密（故不用 services.distribution.mask_account）。
from app.core.utils.crypto_field import mask_account

logger = logging.getLogger(__name__)


def _trusted_hosts() -> set:
    """受信 Host 白名单，由 CORS_ORIGINS 与 H5_BASE_URL 推导。

    Host 是客户端完全可控的请求头，绝不能拿它无条件拼接对外链接：
    攻击者发 `Host: evil.com` 请求本接口，就能拿到 https://evil.com/?ref=xxx，
    分享出去直接变成钓鱼链接。这里只采信运维已显式配置过的域名。
    """
    hosts = set()
    for url in list(settings.cors_origins_list) + [settings.H5_BASE_URL or ""]:
        m = re.match(r"^https?://([^/:\s]+)", (url or "").strip(), re.I)
        if m:
            hosts.add(m.group(1).lower())
    return hosts


router = APIRouter(prefix="/distribution", tags=["分销"])

_COMMISSION_STATUS = {"pending": "待结算", "settled": "已结算", "cancelled": "已冲回"}
_WITHDRAW_STATUS = {"auditing": "审核中", "paid": "已打款", "rejected": "已驳回"}

# A7（第五十九条）：规则重大不利变更的公示文案 + 单独确认留痕（doc_type=rule_change）。
# 提高晋升门槛对存量推广员属不利变更，必须写清「改了什么、对已有等级有无影响」并让用户
# 显式确认：只写「规则已更新」等于没公示，事后无法证明新口径已送达。
# 确认不做硬拦截（不因此禁止推广/提现）：公示与留痕是义务，把未确认变成停权则是处罚。
_RULE_CHANGE_NOTICE = (
    "《分销规则》已更新至 {version}：晋升依据由「验证付费用户数」单一维度调整为"
    "「累计推广业绩为主、验证付费用户数为辅」，两项需同时达标："
    "普通→高级需业绩≥{p1:g} 元且验证付费用户≥{c1} 人；"
    "高级→合伙人需业绩≥{p2:g} 元且验证付费用户≥{c2} 人。"
    "已达到的等级不受影响、不会降级；计佣口径、费率、结算与提现规则均未变更。"
)


def _fmt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M") if dt else None


@router.post("/touch")
async def record_touch(req: TouchRequest, request: Request,
                       db: AsyncSession = Depends(get_db)):
    """推广触达上报（公开）：落地页/二维码被打开时记一次，供 90 天末次触达归因。

    未注册访客调用，故不依赖登录态；代价是任何人都能写 attribution_touch，
    因此按 IP 严格限流，并且只记「邀请码存在且推广员可推广」的触达。
    返回值不区分「邀请码不存在」与「推广员已冻结」——邀请码本身就是公开的推广链接，
    这里再细分只会把「该码是否有效」变成可批量探测的情报。
    """
    if not await redis_rate_limit(redis_client, f"touch_limit:{get_client_ip(request)}",
                                  settings.RATE_LIMIT_TOUCH_PER_HOUR, 3600):
        return error(ErrorCode.RATE_LIMIT, "操作过于频繁，请稍后再试")
    ok = await dist_svc.record_touch(db, req.visitor_key, req.invite_code,
                                     ip=get_client_ip(request),
                                     ua=request.headers.get("user-agent"))
    return success({"recorded": bool(ok)})


@router.get("/status")
async def distributor_status(request: Request, user: User = Depends(get_current_user),
                             db: AsyncSession = Depends(get_db)):
    """推广中心状态：可提现/累计/待结算/已提现/邀请数/成交数/当前费率/最低提现额/邀请链接。

    前端 fillDistribution / fillWithdraw 两处共用本接口；未成为推广员时
    ensure_distributor 自动建号并发邀请码（邀请链接展示所需）。
    """
    enabled = await get_bool(db, "distribution_enabled", settings.DISTRIBUTION_ENABLED)
    if not enabled:
        return success({"enabled": False})
    dist = await ensure_distributor(db, user)
    # 待升等级到生效时刻（达标次日0点）后、定时任务 apply_pending_promotions（每30分钟）
    # 落地前，dist.level 仍是旧值，推广中心会显示过期等级与费率。此处只读地按「已到生效
    # 时刻的待升等级」计算展示等级，消除这段窗口的显示滞后；实际落地仍由调度/计佣路径完成，
    # GET 接口不写库。
    level = int(dist.level or 0)
    if (dist.next_level is not None and dist.next_level_at is not None
            and dist.next_level_at <= datetime.now()):
        level = int(dist.next_level)
    data = {
        "enabled": True,
        "is_distributor": True,
        "level": level,
        "level_name": settings.DIST_LEVEL_NAME.get(level, "普通推广员"),
        "total_commission": float(dist.total_commission or 0),
        "pending_commission": float(dist.pending_commission or 0),
        "available_commission": float(dist.available_commission or 0),
        "withdrawn_commission": float(dist.withdrawn_commission or 0),
        "invite_count": int(dist.invite_count or 0),
        "paid_count": int(dist.paid_count or 0),
        "rate": settings.DIST_LEVEL_BASE_RATE.get(level, 0.30),
        "withdraw_min": float(await get_float(db, "withdraw_min", settings.WITHDRAW_MIN)),
    }
    base_url = (settings.H5_BASE_URL or "").rstrip("/")
    if not base_url:
        # 兜底用本次请求的 Host 拼站点域名：H5_BASE_URL 是最容易漏配的一项
        # （.env.example 里有、线上 .env 里没有），一旦为空，推广中心只显示
        # 「邀请链接未配置」，整条邀请归因链路直接失效。nginx 已下发 Host 与
        # 但 Host 是客户端可控头，无条件采信等于 Host 头注入：攻击者发
        # `Host: evil.com` 请求本接口，拿到的 invite_link 就是
        # https://evil.com/?ref=xxx，分享出去直接变成钓鱼链接。
        # 故只在 Host 命中受信域名（CORS_ORIGINS / H5_BASE_URL 派生）时才采纳。
        host = (request.headers.get("host") or "").strip().lower()
        if host and host in _trusted_hosts():
            scheme = (request.headers.get("x-forwarded-proto") or request.url.scheme or "https")
            scheme = scheme.split(",")[0].strip().lower()
            # scheme 同样做白名单，防止拼出 javascript: / data: 这类伪协议
            if scheme not in ("http", "https"):
                scheme = "https"
            base_url = scheme + "://" + host
        elif host:
            logger.warning(f"邀请链接兜底被拒绝：Host={host} 不在受信域名内（疑似 Host 头注入）")
    data["invite_link"] = f"{base_url}/?ref={dist.invite_code}" if base_url and dist.invite_code else ""
    # A7：晋升进度下发到推广中心。判定与展示必须同源（都走 promotion_progress），
    # 否则用户看到的进度与系统实际判定不一致，会按错误预期去推广。
    data["promote"] = await promotion_progress(db, dist)
    # A7：规则版本与变更公示（按版本号判是否已确认，不能只判「有没有确认过」）
    version = str(await get_config(db, "distribution_rule_version",
                                   settings.DISTRIBUTION_RULE_VERSION) or "")
    confirmed = await consent_svc.latest_agreed_version(db, user.id, consent_svc.DOC_RULE_CHANGE)
    data["rule_version"] = version
    data["rule_confirmed_version"] = confirmed
    pending_notice = bool(version) and confirmed != version
    data["rule_notice_pending"] = pending_notice
    if pending_notice:
        p = settings.DIST_PROMOTE_PERFORMANCE
        c = settings.DIST_PROMOTE_THRESHOLD
        data["rule_notice"] = _RULE_CHANGE_NOTICE.format(
            version=version, p1=p.get(1, 0), c1=c.get(1, 0), p2=p.get(2, 0), c2=c.get(2, 0))
    else:
        data["rule_notice"] = None
    return success(data)


@router.get("/commissions")
async def commission_list(page: int = Query(1, ge=1),
                          page_size: int = Query(20, ge=1, le=50),
                          status: str = Query(None),
                          user: User = Depends(get_current_user),
                          db: AsyncSession = Depends(get_db)):
    """我的服务费流水（该推广员名下订单佣金）。"""
    dist = await ensure_distributor(db, user)
    q = select(CommissionLog).where(CommissionLog.distributor_id == dist.id)
    if status:
        q = q.where(CommissionLog.status == status)
    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar() or 0
    rows = (await db.execute(
        q.order_by(CommissionLog.id.desc()).offset((page - 1) * page_size).limit(page_size)
    )).scalars().all()
    return success({"list": [{
        "id": x.id, "order_no": x.order_no,
        "order_amount": float(x.order_amount),
        "rate": float(x.rate or 0),
        "amount": float(x.amount),
        "status": x.status,
        "status_text": _COMMISSION_STATUS.get(x.status, x.status),
        "created_at": _fmt(x.created_at),
    } for x in rows], "total": total, "page": page, "page_size": page_size})


@router.get("/withdrawals")
async def withdrawal_list(page: int = Query(1, ge=1),
                          page_size: int = Query(20, ge=1, le=50),
                          user: User = Depends(get_current_user),
                          db: AsyncSession = Depends(get_db)):
    """我的提现记录（收款账号脱敏）。"""
    dist = await ensure_distributor(db, user)
    q = select(Withdrawal).where(Withdrawal.distributor_id == dist.id)
    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar() or 0
    rows = (await db.execute(
        q.order_by(Withdrawal.id.desc()).offset((page - 1) * page_size).limit(page_size)
    )).scalars().all()
    return success({"list": [{
        "id": x.id, "withdraw_no": x.withdraw_no,
        "amount": float(x.amount),
        "tax_amount": float(x.tax_amount or 0),
        "actual_amount": float(x.actual_amount) if x.actual_amount is not None else None,
        "status": x.status,
        "status_text": _WITHDRAW_STATUS.get(x.status, x.status),
        "channel": x.channel,
        "account_mask": mask_account(x.channel, x.account_no),
        "created_at": _fmt(x.created_at),
    } for x in rows], "total": total, "page": page, "page_size": page_size})


@router.post("/withdraw")
async def withdraw(req: WithdrawRequest, user: User = Depends(get_current_user),
                   db: AsyncSession = Depends(get_db)):
    """申请提现（审核制：行锁 + 实名风控 + 每日次数 + 个税代扣，见 services.apply_withdrawal）。"""
    enabled = await get_bool(db, "distribution_enabled", settings.DISTRIBUTION_ENABLED)
    if not enabled:
        return error(ErrorCode.PARAM_ERROR, "推广功能暂未开放")
    ok, msg, wd = await apply_withdrawal(
        db, user, req.amount, req.channel, req.account_name, req.account_no)
    if not ok:
        return error(ErrorCode.PARAM_ERROR, msg)
    return success({"withdraw_no": wd.withdraw_no,
                    "amount": float(wd.amount),
                    "tax_amount": float(wd.tax_amount or 0),
                    "actual_amount": float(wd.actual_amount or 0),
                    "msg": msg})


@router.get("/team")
async def team_list(user: User = Depends(get_current_user),
                    db: AsyncSession = Depends(get_db)):
    """我的团队：直接邀请的用户及其付费状态（有已完成订单即视为已付费）。
    昵称一律走 _mask_rank_nick 脱敏（与排行榜同口径）：团队成员昵称同样是
    其他用户的个人信息，推广员运营需要的是「几个成员、谁付费了」的规模事实，
    不需要拿到完整昵称；无昵称成员统一显示「道友 + uid 后 4 位」。"""
    await ensure_distributor(db, user)
    members = (await db.execute(
        select(User).where(User.inviter_id == user.id).order_by(User.id.desc()).limit(100)
    )).scalars().all()
    uids = [m.id for m in members]
    paid_map = {}
    if uids:
        rows = (await db.execute(
            select(Order.user_id, func.min(Order.paid_at)).where(
                Order.user_id.in_(uids), Order.status == "completed",
                # 排除会员期内 ensure-report 生成的 0 元 vip_*_view 单：它们 status=completed、
                # paid_at 非空，但并非真实付费。否则管理员赠送会员的用户仅凭 0 元消费单就会
                # 被误标为「已付费」（与 on_order_paid「0 元单不计佣、不计业绩」口径一致）。
                Order.amount > 0,
                Order.paid_at.isnot(None)).group_by(Order.user_id))).all()
        paid_map = {r[0]: r[1] for r in rows}
    return success({"list": [{
        "user_id": _mask_uid(m.id),
        "nickname": _mask_rank_nick(m.id, m.nickname or ""),
        "paid": m.id in paid_map,
        "paid_at": _fmt(paid_map[m.id]) if m.id in paid_map else None,
        "joined_at": _fmt(m.invited_at or m.created_at),
        "created_at": _fmt(m.created_at),
    } for m in members], "total": len(members)})


def _mask_uid(user_id: int) -> str:
    """P3 修复：用户端团队列表不再下发完整自增 user_id（与排行榜口径一致，
    避免 ID 枚举/爬取用户规模），仅返回尾 4 位。前端仅在昵称为空时用它做展示，
    而昵称已由 _mask_rank_nick 保证恒非空（兜底「道友+尾4位」）。"""
    s = str(user_id)
    return s[-4:] if len(s) > 4 else s


def _mask_rank_nick(user_id: int, nick: str) -> str:
    """排行榜昵称脱敏：不全站公示真实昵称。
    有昵称：1 字→「张**」，2 字→「张*」，3 字及以上→「张**三」（首尾各露一字）；
    无昵称：统一「道友 + uid 后 4 位」，避免直接暴露内部自增 ID 全量。"""
    s = (nick or "").strip()
    if not s:
        return f"道友{user_id % 10000:04d}"
    if len(s) == 1:
        return s + "**"
    if len(s) == 2:
        return s[0] + "*"
    return s[0] + "**" + s[-1]


@router.get("/ranking")
async def dist_ranking(month: str = Query(None),
                       user: User = Depends(get_current_user),
                       db: AsyncSession = Depends(get_db)):
    """推广排行榜（用户侧）：当月实时预估全站前 20 + 本人战绩 + 奖金档位。

    - 数据源与次月 8 号结算完全同源（distribution_rank.get_top_ranking/get_my_month）：
      名次按「月度推广总金额」竞赛排名（并列同名次），未达名次门槛不发、不降档、不替补；
    - 当月数据为实时预估，不构成奖励承诺，最终以次月 {settle_day} 号结算为准；
    - 昵称一律脱敏后下发，服务端不向前端返回真实昵称；
    - tiers 为奖金档位表，数值取自 settings.DIST_RANK_REWARD，前端不写死任何金额/门槛。
    """
    dist = await ensure_distributor(db, user)
    if not month or not re.fullmatch(r"\d{4}-\d{2}", month.strip()):
        month = datetime.now().strftime("%Y-%m")
    month = month.strip()
    enabled = await get_bool(db, "distribution_enabled", settings.DISTRIBUTION_ENABLED)
    top_rows = await get_top_ranking(db, month, limit=20) if enabled else []
    mine = await get_my_month(db, dist.id, month) if enabled else {
        "month": month, "total_amount": 0.0, "ladder_uplift": 0.0,
        "est_rank": None, "est_reward": 0.0, "settled": False,
        "final_rank": None, "rank_reward": 0.0, "ladder_adjust": 0.0,
    }
    tiers = [{
        "rank_from": int(lo), "rank_to": int(hi),
        "reward": float(reward), "threshold": float(threshold),
    } for lo, hi, reward, threshold in settings.DIST_RANK_REWARD]
    ladder = sorted(
        ({"threshold": float(t), "uplift": float(u)} for t, u in settings.DIST_LADDER),
        key=lambda x: x["threshold"])
    return success({
        "enabled": bool(enabled),
        "month": month,
        "list": [{
            "rank": x["rank"],
            "name": _mask_rank_nick(x["user_id"], x["nickname"]),
            "me": x["user_id"] == user.id,
            "total_amount": x["total_amount"],
            "reward": x["reward"],
        } for x in top_rows],
        "mine": mine,
        "tiers": tiers,
        "ladder": ladder,
        "pool_cap": float(rank_pool_cap()),
        "settle_day": settings.DIST_MONTHLY_SETTLE_DAY,
    })


@router.get("/rules")
async def dist_rules(user: User = Depends(get_current_user),
                     db: AsyncSession = Depends(get_db)):
    """推广规则完整文案（共 11 项：模式/等级/晋升/计佣/阶梯/排行/结算/归因/提现/纳税/合规）。

    原实现只硬编码返回 5 个字段，遗漏了等级/晋升/阶梯/排行/结算/归因等核心规则，
    且与 SQL seed 的完整 distribution_rules 配置脱节。现改为以 settings 为权威来源
    逐项构建完整 11 字段（数值与实际生效规则一致），system_configs.distribution_rules
    可按键覆盖（运营自定义）。sections 为按固定顺序的展示数组。

    A7：本接口只负责「规则全文」，不负责「变更公示」：公示条与确认留痕在 /status
    下发（推广中心首屏）。分开是有意的：规则全文每次进页都读，而公示只在版本号与
    已确认版本不一致时才需弹出；把两者合并会让公示逻辑随规则页一起被缓存或跳过。
    """
    rules = await build_distribution_rules(db)
    version = await get_config(db, "distribution_rule_version", settings.DISTRIBUTION_RULE_VERSION)
    sections = [{"key": k, "label": lb, "value": rules[k]}
                for k, lb in DISTRIBUTION_RULE_LABELS if rules.get(k)]
    return success({"version": version, "rules": rules, "sections": sections})
