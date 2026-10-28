"""
会员服务 —— 对齐《会员体系规则 V1.3》
- 三档：月卡/年卡/终身，固定天数制（月30天、年365天、终身永久）
- 宽限期72h：到期后权益按免费处理，仅保留 continuous_flag 连续身份标记
- 全价升级：月→年→终身，升级按新档全价、不折算差价；旧档剩余整天叠加顺延到新档到期日
- 续费：未到期/宽限期内在原到期时刻顺延；宽限期后视为新购
- 额度：周期总额度为全部工具共享总池 + 单工具单日上限 + bonus 赠送额度（见 services/quota.py）
- 保留既有 MembershipLedger 发放/回滚精确清算逻辑
"""
import logging
from datetime import datetime, timedelta
from typing import Optional
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError
from app.core.models import UserMembership, MembershipLedger
from app.core.database import row_lock
from app.config import settings
from app.core.services.config_helper import get_config

logger = logging.getLogger(__name__)

# SKU -> 档位
# 会员档位 SKU（month/year/lifetime）由插件 manifest 声明、注册表聚合，见 level_of_sku
# 档位 -> 固定天数（终身为 None=永久）
LEVEL_DAYS = {"month": settings.MEMBERSHIP_MONTH_DAYS,
              "year": settings.MEMBERSHIP_YEAR_DAYS,
              "lifetime": None}
# 档位高低（升级只允许低→高）
LEVEL_RANK = {"none": 0, "month": 1, "year": 2, "lifetime": 3}
TIER_NAME = settings.MEMBERSHIP_TIER_NAME

def _member_covered_single_skus():
    # 会员已覆盖工具对应的单次 SKU：会员有效期内屏蔽这些单次购买（第三十一条）。
    # 由插件 manifest 的 member_included 声明、注册表聚合。
    from app.plugins import registry
    return registry.member_covered_single_skus()


def level_of_sku(sku_code: str) -> Optional[str]:
    # 档位 SKU -> level：先按各插件 manifest.membership_skus 反查（业务自定义码优先），
    # 查不到再回落到 settings.MEMBERSHIP_TIER_SKUS —— 底座商品就是按这张表播种的，
    # 两边必须同源，否则「商品能下单、履约认不出档位」会在用户付款后才炸。
    from app.plugins import registry
    _, level = registry.membership_level_by_sku(sku_code)
    if level:
        return level
    return {sku: lvl for lvl, sku in settings.MEMBERSHIP_TIER_SKUS.items()}.get(sku_code)


def days_for_level(level: str) -> Optional[int]:
    return LEVEL_DAYS.get(level)


def quota_conf(level: str) -> dict:
    """该档位的额度配置；未知档位返回全0（不放行任何测算）。"""
    return settings.MEMBERSHIP_QUOTA.get(level, {"period_days": 0, "period_total": 0,
                                                 "daily_per_tool": 0, "archive_limit": 0})


async def get_membership(db: AsyncSession, user_id: int, for_update: bool = False):
    stmt = select(UserMembership).where(UserMembership.user_id == user_id)
    if for_update:
        stmt = row_lock(stmt)
    return (await db.execute(stmt)).scalar_one_or_none()


def _grace_deadline(expire_at: Optional[datetime]) -> Optional[datetime]:
    if not expire_at:
        return None
    return expire_at + timedelta(hours=settings.MEMBERSHIP_GRACE_HOURS)


def period_window(m: UserMembership, level: str, now: datetime):
    """当前额度周期窗口 [start, end)。
    月/年：自 start_at 起每 period_days 滚动；终身：自 start_at 起每365天滚动。
    返回 (period_start, period_end)；period_end 对终身也为有限值（用于展示下次重置日）。
    """
    conf = quota_conf(level)
    pdays = conf.get("period_days") or 365
    base = m.period_start or m.start_at or now
    # 从 base 起按 pdays 步进，找到覆盖 now 的那个周期起点
    start = base
    if now >= start:
        n = int((now - start).total_seconds() // (pdays * 86400))
        start = base + timedelta(days=n * pdays)
    end = start + timedelta(days=pdays)
    return start, end


async def _period_used(db: AsyncSession, user_id: int, p_start: datetime,
                       p_end: datetime, now: datetime) -> int:
    """本周期总池已用次数（事实来源=订单表，与 quota.consume 的判定完全同源）。

    函数级导入 quota：services.quota 在模块级反向导入本模块（get_member_status /
    quota_conf），模块级导入会构成循环导入。
    """
    from app.core.services import quota as quota_svc
    # sku_view 传空串：只取总池 period_used，daily_used 在此无意义
    u = await quota_svc.usage(db, user_id, "", p_start, p_end, now=now)
    return int(u["period_used"])


async def get_member_status(db: AsyncSession, user_id: int, now: Optional[datetime] = None,
                            with_usage: bool = False) -> dict:
    """会员状态 + 额度可见性（第二十六条）。
    返回 is_vip 仅在「有效期内」为真；宽限期内 is_vip=False、in_grace=True。

    period_used：本周期总池已用次数。默认不统计（保持 0），因为本函数处在
    check_feature -> is_vip 的每次鉴权热路径上，而额度统计要多跑一次 COUNT；
    需要展示额度的调用方（GET /membership/status）显式传 with_usage=True 换取。

    原实现从不给 period_used 赋值：base 恒为 0，两个 is_vip 分支都只是 {**base, ...}
    覆盖其他字段，于是所有会员的「本周期已用 / 总额度」永远显示 0/N——用户看不到额度
    消耗，被拦（QUOTA_EXCEEDED）时更无从判断撞的是周期总池还是单工具单日上限。
    """
    now = now or datetime.now()
    m = await get_membership(db, user_id)
    base = {"is_vip": False, "level": "none", "tier_name": None, "expire_at": None,
            "days_remain": 0, "in_grace": False, "continuous": False,
            "period_total": 0, "period_used": 0, "bonus_quota": 0, "bonus_used": 0,
            "daily_per_tool": 0, "archive_limit": 0, "period_reset_at": None,
            "remain_seconds": 0}
    if not m or m.level == "none":
        return base

    level = m.level
    conf = quota_conf(level)
    tier = TIER_NAME.get(level)

    # 终身：永久有效
    if level == "lifetime":
        p_start, p_end = period_window(m, level, now)
        out = {**base, "is_vip": True, "level": level, "tier_name": tier,
               "expire_at": None, "days_remain": -1, "in_grace": False,
               "continuous": bool(m.continuous_flag),
               "period_total": conf["period_total"], "bonus_quota": m.bonus_quota or 0,
               "bonus_used": m.bonus_used or 0, "daily_per_tool": conf["daily_per_tool"],
               "archive_limit": conf["archive_limit"],
               "period_reset_at": p_end.strftime("%Y-%m-%d %H:%M:%S")}
        if with_usage:
            out["period_used"] = await _period_used(db, user_id, p_start, p_end, now)
        return out

    # 月/年：判断有效期 / 宽限期 / 已失效
    expire_at = m.expire_at
    if expire_at and expire_at > now:
        remain = expire_at - now
        days = remain.days + (1 if remain.seconds else 0)
        p_start, p_end = period_window(m, level, now)
        out = {**base, "is_vip": True, "level": level, "tier_name": tier,
               "expire_at": expire_at.strftime("%Y-%m-%d %H:%M:%S"),
               "days_remain": days, "remain_seconds": int(remain.total_seconds()),
               "in_grace": False, "continuous": bool(m.continuous_flag),
               "period_total": conf["period_total"], "bonus_quota": m.bonus_quota or 0,
               "bonus_used": m.bonus_used or 0, "daily_per_tool": conf["daily_per_tool"],
               "archive_limit": conf["archive_limit"],
               "period_reset_at": p_end.strftime("%Y-%m-%d %H:%M:%S")}
        if with_usage:
            out["period_used"] = await _period_used(db, user_id, p_start, p_end, now)
        return out

    # 已到期：宽限期内权益=免费，仅保留连续标记
    gd = _grace_deadline(expire_at)
    if gd and gd > now:
        return {**base, "is_vip": False, "level": "none", "tier_name": None,
                "expire_at": expire_at.strftime("%Y-%m-%d %H:%M:%S") if expire_at else None,
                "days_remain": 0, "in_grace": True, "continuous": bool(m.continuous_flag)}

    return base


async def is_vip(db: AsyncSession, user_id: int) -> bool:
    return (await get_member_status(db, user_id))["is_vip"]


async def assert_can_buy(db: AsyncSession, user_id: int, sku_code: str) -> Optional[str]:
    """购买前置校验：返回非空串=拒绝原因。
    - 终身会员不可再购买/升级任何会员（第三十八条第2款）
    - 已有会员不可重复购买同档或更低档，只允许升级更高档或到期后续费（第三十八条第1款）
    - 宽限期内权益已失效，购买更高档或同档均放行，自当日重新起算——此处只拦「同档/更低档」。
    """
    level = level_of_sku(sku_code)
    st = await get_member_status(db, user_id)
    if not level:
        # 单次/按天商品：会员有效期内屏蔽「会员已覆盖工具」的单次购买入口（第三十一条），
        # 避免重复付费；到期（含宽限期）后 is_vip=False，入口自动恢复。
        # 日常工具 wuxing_day 不属于会员权益（运营裁定仅保留接口），会员仍可正常购买，不屏蔽。
        if st["is_vip"] and sku_code in _member_covered_single_skus():
            return "会员有效期内已解锁全部完整报告，无需重复单次购买"
        return None
    cur = st["level"] if st["is_vip"] else "none"
    if cur == "lifetime":
        return "您已是终身会员，全部功能已解锁，无需重复购买"
    if st["in_grace"]:
        # 宽限期内：权益已失效、无剩余可顺延，购买更高档或同档均放行，自当日重新起算
        return None
    if cur != "none" and LEVEL_RANK[level] <= LEVEL_RANK[cur]:
        return "当前会员有效期内不可重复购买同档或更低档位，可选择升级更高档或到期后续费"
    return None


async def card_redeem_block_reason(db: AsyncSession, user_id: int, sku_code: str) -> str:
    """会员卡兑换前置校验：返回非空串=拒绝原因。

    与 grant_membership 的降档保护配套。那里是最后一道兜底（保住数据不降档），
    但卡密在那条路径上已经被置 used —— 用户既没换到档位、又白扔一张卡。
    这里在「建单 / 发放之前」拦下并抛 CardRedeemError，整笔兑换事务回滚，
    卡密仍为 unused，用户可在现有会员到期后再兑，也可以转赠他人。

    与 assert_can_buy 的差别（两者必须口径一致，但用途不同）：
      · assert_can_buy 管「付钱买」，只在**下单那一刻**校验；
      · 本函数管「拿卡兑」，在**兑换那一刻**校验，覆盖下单后档位才变化的窗口。
    仅在「当前会员仍有效（未到期或宽限期内）且档位高于该卡」时拒绝；
    已过宽限期视为新购，与第三十八条「宽限期后视为新购」一致。
    """
    level = level_of_sku(sku_code)
    if not level:
        return ""
    m = await get_membership(db, user_id)
    if not m or m.level == "none":
        return ""
    if m.level == "lifetime":
        # 原先对「终身会员 + 终身卡」
        # 直接放行（return ""），而 grant_membership 的终身分支每次发放都会重新
        # _reset_period（period_start=now、赠送额度清零）；可终身卡对终身会员**没有任何
        # 新增权益**（档位与到期日均不变），于是这次兑换唯一的效果就是「把 365 天额度
        # 周期重开一轮」—— 用户白扔一张卡，平台 3000 次额度池被凭空刷新。
        # 与第三十八条「终身为最高档，不可再购买/升级」及 assert_can_buy 口径统一：一律拒绝。
        return ("您已是终身会员，全部功能已永久解锁，该卡不会带来任何新增权益；"
                "卡密仍然有效，可转赠他人")
    now = datetime.now()
    grace_deadline = _grace_deadline(m.expire_at)
    still_valid = (bool(m.expire_at and m.expire_at > now)
                   or bool(grace_deadline and grace_deadline > now))
    if still_valid and LEVEL_RANK.get(level, 0) < LEVEL_RANK.get(m.level, 0):
        return (f"您当前是{TIER_NAME.get(m.level, m.level)}会员，档位高于该卡；"
                "兑换会降低档位，请留待现有会员到期后再兑换（卡密仍然有效）")
    return ""


async def _get_or_create_locked(db: AsyncSession, user_id: int, now: datetime) -> UserMembership:
    """行锁获取会员记录；不存在则创建，并发唯一约束冲突时回退到重新加锁查询"""
    m = await get_membership(db, user_id, for_update=True)
    if m:
        return m
    m = UserMembership(user_id=user_id, level="none", start_at=now)
    try:
        async with db.begin_nested():
            db.add(m)
    except IntegrityError:
        m = await get_membership(db, user_id, for_update=True)
        if not m:
            raise
    return m


def _reset_period(m: UserMembership, now: datetime, level: str):
    """开通/升级/进入新周期时：额度周期重起、bonus 清零（第二十四条第4款、第三十五条第3款）。"""
    m.period_start = now
    m.bonus_quota = 0
    m.bonus_used = 0


async def grant_membership(db, user_id, sku_code, order_no, days=None, order_id=None,
                           pay_amount=None) -> UserMembership:
    """支付成功后发放会员（方案B：全价 + 剩余叠加顺延）。自动区分 新购 / 续费 / 升级：
    - 无有效会员 / 宽限期恢复 → 新购：自支付时刻起算（旧到期日已失效，base=now）
    - 有效会员买更高档 → 升级：按新档全价，到期日在旧卡剩余之上顺延叠加新档天数（不折算差价）
    - 有效会员买同档 → 续费：在原到期时刻顺延
    终身：level=lifetime、expire_at=None、period_start=now（每365天滚动重置额度）。
    """
    now = datetime.now()
    level = level_of_sku(sku_code)
    if not level:
        raise ValueError(f"非会员SKU: {sku_code}")
    # 幂等兜底：同一订单只发放一次会员。MembershipLedger.order_id 无唯一约束（不同于 Report/
    # CommissionLog），并发重复由上游 _mark_order_paid 的 CAS 抢占挡住；此处挡的是「串行重放」——
    # 支付回调首次提交后再次投递、或经其他补触发路径二次进入本函数。已存在本单的 grant 流水即视为
    # 已发放，直接返回当前会员，避免续费到期时刻被二次顺延、重复叠加发放流水（口径对齐
    # entitlement.grant_entitlement 的先查后返回、distribution.on_order_paid 的 CommissionLog 先查后插）。
    if order_id:
        granted = (await db.execute(select(MembershipLedger.id).where(
            MembershipLedger.order_id == order_id,
            MembershipLedger.action == "grant"))).scalars().first()
        if granted:
            logger.info(f"会员已按订单发放，幂等跳过重复发放 order_id={order_id} user_id={user_id}")
            return await get_membership(db, user_id)
    m = await _get_or_create_locked(db, user_id, now)
    st = await get_member_status(db, user_id, now=now)
    cur_level = st["level"] if st["is_vip"] else "none"
    grant_days = 0

    if level == "lifetime":
        m.level = "lifetime"
        m.expire_at = None
        m.start_at = now
        m.continuous_flag = 1
        m.rule_version = settings.MEMBERSHIP_RULE_VERSION
        _reset_period(m, now, level)
    else:
        d = days or days_for_level(level) or settings.MEMBERSHIP_MONTH_DAYS
        is_upgrade = cur_level != "none" and LEVEL_RANK[level] > LEVEL_RANK[cur_level]
        reset_period = is_upgrade or cur_level == "none" or st["in_grace"]
        # 方案B（全价）：月/年卡到期时刻一律「顺延叠加」——base 取现有未过期到期日，否则从今起算。
        # 旧档剩余整天叠加保留（升级付新档全价，不再折算补差价，已付费时长不浪费）。
        #
        # 宽限期顺延：/membership/rules 的 grace 条款与本模块 docstring 都写明
        # 「宽限期内续费在原到期时刻顺延」，而原条件只认 `expire_at > now`——宽限期内
        # expire_at 已经过期，base 被落到 now，用户比公示规则少得「宽限期已耗掉的时长」
        # （到期 2 天后续费就少 2 天）。公示文案即对用户的承诺，实现必须与之一致。
        grace_deadline = _grace_deadline(m.expire_at)
        in_grace_now = bool(grace_deadline and grace_deadline > now)
        base = m.expire_at if (m.expire_at and (m.expire_at > now or in_grace_now)) else now
        #
        # 降档保护：当前会员仍有效（未到期，或在宽限期内）且档位高于本次发放档位时，
        # 绝不能把 level 降下来。admin_grant_membership 早已有同样判断，但本函数——
        # 「支付到账」与「卡密兑换」两条真实资损路径的唯一发放口——漏掉了：
        #   · 卡密兑换完全不经过 assert_can_buy（它只在下单那一刻校验），终身会员兑一张
        #     vip_month 卡，level 会被由 lifetime 覆盖成 month、expire_at 由 NULL 变成
        #     +30 天，终身资格不可逆销毁，额度池同时从 3000/365天 掉到 100/30天；
        #   · 付费路径的下单与到账之间同样有窗口：先下单月卡、期间买了年卡并支付成功，
        #     随后才支付那张月卡单 —— assert_can_buy 在下单时是拦不住的。
        # 处置：保留高等级档位，只把本次购买的天数顺延叠加到现有到期日；终身档没有到期日
        # 可顺延，故只保住终身身份（本次购买不加时长，但绝不作废用户既有权益）。
        # 仍照常写 grant 流水：退款清算依赖台账，档位回退由 rollback_membership 负责。
        if (m.level != "none" and LEVEL_RANK.get(m.level, 0) > LEVEL_RANK[level]
                and (m.expire_at is None or m.expire_at > now or in_grace_now)):
            logger.warning(
                "会员发放降档已拦截：保留高等级档位 user_id=%s cur=%s want=%s order_id=%s",
                user_id, m.level, level, order_id)
            if m.level != "lifetime":
                m.expire_at = base + timedelta(days=d)
        else:
            m.level = level
            m.start_at = now if reset_period else (m.start_at or now)
            m.expire_at = base + timedelta(days=d)
            if reset_period:
                _reset_period(m, now, level)
        # 第四十五条：获得有效会员身份即为「连续会员」，continuous_flag 置1；只有
        # 「超宽限期未续费」由 expire_overdue 清0、退款/管理员撤销由对应路径清0。
        m.continuous_flag = 1
        grant_days = d
        m.rule_version = settings.MEMBERSHIP_RULE_VERSION

    m.source_order_no = order_no
    if order_id:
        db.add(MembershipLedger(user_id=user_id, order_id=order_id, order_no=order_no,
                                level=level, grant_days=grant_days, action="grant"))
    await db.flush()
    return m


async def admin_grant_membership(db, user_id, action, days=None) -> UserMembership:
    now = datetime.now()
    m = await _get_or_create_locked(db, user_id, now)
    if action in ("grant_lifetime", "grant_month", "grant_year"):
        level = {"grant_lifetime": "lifetime", "grant_month": "month", "grant_year": "year"}[action]
        if level == "lifetime":
            m.level = "lifetime"
            m.expire_at = None
            m.start_at = now
            m.continuous_flag = 1
            _reset_period(m, now, level)
        else:
            d = days or days_for_level(level) or settings.MEMBERSHIP_MONTH_DAYS
            # 终身卡不可被月/年卡覆盖（原意），且**仍在有效期内**的高等级卡不可被低等级卡降档。
            # 原条件写作 `LEVEL_RANK[level] <= LEVEL_RANK[m.level ...] and m.level == "lifetime"`：
            # and 之后的前半段比较整体失效，等价于只判 lifetime。于是给有效期内的年卡补发一张
            # 月卡会把 level 降成 month（额度池从 1200 缩到 100），却仍按旧到期日顺延——
            # 用户实得权益缩水、台账却显示「已延长」，是管理员按一下就会发生的资损与纠纷。
            # 注意只在「当前卡仍有效」时拦：已过期的年卡用户补发月卡是正常的重新开卡。
            # 同档补发仍放行（= 续期），这是运营常用动作，不能一并拦掉。
            if m.level == "lifetime":
                return m
            if m.level != "none" and m.expire_at and m.expire_at > now \
                    and LEVEL_RANK[level] < LEVEL_RANK[m.level]:
                logger.info("管理员补发被跳过：目标档位低于当前有效档位 user_id=%s cur=%s want=%s",
                            user_id, m.level, level)
                return m
            base = m.expire_at if (m.expire_at and m.expire_at > now) else now
            m.level = level
            m.start_at = m.start_at or now
            m.expire_at = base + timedelta(days=d)
            m.continuous_flag = 1
            m.rule_version = settings.MEMBERSHIP_RULE_VERSION
            # 与 grant_membership 保持一致——「失效后重开/首次发放」（base==now）必须重起
            # 额度周期并清零 bonus。原实现漏掉本步，管理员补发月/年卡时会沿用旧的 period_start，
            # 使额度周期窗口错位（quota.period_window 以 period_start 为锚滚动），且过期会员残留的
            # bonus_quota/bonus_used 被带入新周期，导致额度显示与扣减都不对。
            # 「在原到期时刻顺延」的续期（base!=now）不重置，与付费续费的语义一致。
            if base == now:
                _reset_period(m, now, level)
    elif action == "revoke":
        m.level = "none"
        m.expire_at = None
        m.continuous_flag = 0
        m.bonus_quota = 0
        m.bonus_used = 0
    else:
        raise ValueError(f"未知管理动作: {action}")
    await db.flush()
    return m


async def rollback_membership(db, user_id, sku_code, order_id=None, days=None) -> None:
    """
    退款回滚：
    - 月/年卡：按该订单 ledger 发放天数精确作废；无流水（历史数据）才扣固定天数。
      即便当前 level 已变（被更高档覆盖或已过期）也落一条作废流水。
    - 终身：收回终身身份；若历史上还有未退款且未过期的月/年卡，按真实剩余时长回退。
    退款后清零 bonus、收回连续标记（第四十八条第4款）。
    """
    level = level_of_sku(sku_code)
    if days is None:
        days = days_for_level(level) or settings.MEMBERSHIP_MONTH_DAYS
    m = await get_membership(db, user_id, for_update=True)
    if not m:
        return
    now = datetime.now()
    if level == "lifetime":
        # 升级到终身单退款时，恢复升级前的旧档会员（月/年卡），不再一律降回 month。
        old_level, left = await _remaining_membership_from_ledger(db, user_id, exclude_order_id=order_id)
        if old_level != "none" and left and left > 0:
            m.level = old_level
            m.expire_at = now + timedelta(days=left)
            # 额度周期锚同步回退：升级到终身会把 period_start 推到终身发放那一刻，
            # 退款后不还原就等于白得一个周期（详见 _revert_period_anchor）。
            await _revert_period_anchor(db, m, user_id, order_id)
        else:
            m.level = "none"
            m.expire_at = None
        m.bonus_quota = 0
        m.bonus_used = 0
        m.continuous_flag = 0
        if order_id:
            db.add(MembershipLedger(user_id=user_id, order_id=order_id, order_no="",
                                    level="lifetime", grant_days=0, action="rollback"))
        await db.flush()
    elif level in ("month", "year"):
        deduct = days
        if order_id:
            led = (await db.execute(select(MembershipLedger).where(
                MembershipLedger.order_id == order_id, MembershipLedger.action == "grant"))).scalars().first()
            if led is not None:
                deduct = led.grant_days or 0
            db.add(MembershipLedger(user_id=user_id, order_id=order_id, order_no="",
                                    level=level, grant_days=deduct, action="rollback"))
        # 原条件 `m.level == level` 在「升级后退款旧低档单」时会整体跳过重算——
        # 买月卡 → 升级年卡（level 变 year）→ 退款那张月卡单：level("month") != m.level
        # ("year")，于是只落一条作废流水而 m.expire_at 分文未减，用户白得 30 天。
        # 台账推算（_remaining_membership_from_ledger）本就排除了本单与所有已作废单，
        # 对任意档位组合都成立，因此只要「当前是月/年档」就进入；lifetime 必须排除，
        # 否则退款一张历史月卡会把终身档位一起推算掉。
        if m.level in ("month", "year") and m.expire_at:
            # 方案B（全价+顺延叠加）退款精准回退：以台账推演「除本单外其余未作废月/年卡」
            # 此刻应剩的档位与天数为准。台账逐单精确记录 grant_days，比单纯「扣本单天数」更准——
            # 升级退款据此降回旧档（旧模型 level 卡在高档、权益泄漏），到期归零据此退回非会员。
            reverted_expire = m.expire_at - timedelta(days=deduct)
            old_level, left = await _remaining_membership_from_ledger(db, user_id, exclude_order_id=order_id)
            if old_level != "none" and left > 0:
                # 仍有其他未作废的月/年卡：回落到其档位与真实剩余天数（覆盖升级降档、续费退款）
                m.level = old_level
                m.expire_at = now + timedelta(days=left)
                # 额度周期锚同步回退：grant_membership 在升档/新购/宽限期续费时会
                # _reset_period 把 period_start 前移（额度周期重起），而 quota.usage
                # 统计 created_at >= period_start —— 锚不回滚的话，「升年卡 → 用满额度
                # → 退款」就等于白得一个完整额度周期（详见 _revert_period_anchor）。
                await _revert_period_anchor(db, m, user_id, order_id)
            elif reverted_expire > now:
                # 台账无其他有效卡，但扣本单天数后仍未过期（同档续费且老数据无流水）：保档位、用扣减结果
                m.expire_at = reverted_expire
            else:
                # 已无任何有效会员：退回非会员并清零额度与连续标记
                m.level = "none"
                m.expire_at = None
                m.bonus_quota = 0
                m.bonus_used = 0
                m.continuous_flag = 0
        await db.flush()


async def _period_anchor_from_ledger(db, user_id, exclude_order_id=None) -> Optional[datetime]:
    """推算「除本单外」此刻应有的额度周期锚（period_start）。

    背景：
    grant_membership 在「新购 / 升档 / 宽限期续费」时会经 _reset_period 把 period_start
    前移（额度周期重起），但 rollback_membership 只还原档位、到期日、赠送额度与连续标记，
    **从不还原 period_start**。而 quota.period_window 以 period_start 为锚滚动、
    quota.usage 统计 `created_at >= period_start` —— 锚被前移等于「本周期已消耗次数全部
    归零」。于是「升年卡 → 用满额度（报告生成但不打开，客服即判未使用）→ 退款」可以白得
    一个完整年度额度周期，升级期间已消耗的额度也不会被追回。

    这里按流水时间顺序重放，reset 判定与 grant_membership 完全同一口径：
        reset = 首次开通「前序档位 none」/ 升档 / 宽限期内续费
    返回最后一次触发 reset 的发放时刻；无有效发放时返回 None。

    已知精度边界：管理员补发（admin_grant_membership）不写 MembershipLedger，重放可能
    漏掉那次 reset。因此调用方 _revert_period_anchor 必须「只提前、不推后」地使用本结果
    —— 宁可少给额度，也不能凭不完整台账多给。
    """
    rows = (await db.execute(select(MembershipLedger).where(
        MembershipLedger.user_id == user_id,
        MembershipLedger.level.in_(["month", "year", "lifetime"]),
        MembershipLedger.action.in_(["grant", "rollback"])))).scalars().all()
    voided = {r.order_id for r in rows
              if r.action == "rollback" and r.order_id is not None}
    grants = [r for r in rows
              if r.action == "grant" and r.order_id != exclude_order_id
              and (r.order_id is None or r.order_id not in voided)]
    grants.sort(key=lambda r: (r.created_at or datetime.max, r.id or 0))
    level = "none"
    expire_at = None
    anchor = None
    for r in grants:
        t = r.created_at or datetime.now()
        if r.level == "lifetime":
            # 终身分支每次发放都是「从头开始」，不存在顺延：档位/到期日重置、周期重起
            level, expire_at, anchor = "lifetime", None, t
            continue
        d = r.grant_days or 0
        if d <= 0:
            continue
        is_upgrade = (level != "none"
                      and LEVEL_RANK.get(r.level, 0) > LEVEL_RANK.get(level, 0))
        grace_end = _grace_deadline(expire_at)
        in_grace = bool(expire_at and expire_at <= t and grace_end and grace_end > t)
        if is_upgrade or level == "none" or in_grace:
            anchor = t
        base = expire_at if (expire_at and (expire_at > t or in_grace)) else t
        expire_at = base + timedelta(days=d)
        level = r.level
    return anchor


async def _revert_period_anchor(db, m, user_id, exclude_order_id) -> None:
    """退款回滚时把额度周期锚拉回「除本单外」应有的位置（只提前、不推后）。

    只在「本单的发放就是把锚推到当前位置的那一次」时生效：此时重放结果必然早于当前
    period_start，回落即等价于「当作本单从未发生」。若重放结果不早于当前锚，说明本单
    没有推动过周期（同档续费 / 台账缺失的管理员补发），一律不动 —— 这一侧的不动是为了
    不凭不完整台账放宽额度口径。

    典型修复场景：月卡用户用满 100 次 → 升年卡（period_start 被推到此刻，本周期已消耗
    次数全部归零）→ 再用满年卡额度 → 退款年卡。此处把锚推回升级前那一刻，本周期已
    消耗次数重新计入，白得周期的路径消失。
    """
    anchor = await _period_anchor_from_ledger(db, user_id,
                                              exclude_order_id=exclude_order_id)
    if not anchor:
        return
    if m.period_start is not None and anchor >= m.period_start:
        return
    logger.info(f"退款回滚额度周期锚 user={user_id} anchor={anchor:%Y-%m-%d %H:%M} "
                f"period_start_before={m.period_start} exclude_order_id={exclude_order_id}")
    m.period_start = anchor
    if m.start_at is None or anchor < m.start_at:
        m.start_at = anchor


async def _remaining_membership_from_ledger(db, user_id, exclude_order_id=None) -> tuple:
    """推算除本次退款订单外，其他月/年卡到此刻还剩的 (档位, 天数)。

    按流水时间顺序推演：最后一段未作废的有效发放决定档位（月→年演进的最后一档），
    到期时刻由剩余天数推算。返回 (level, days)；无剩余时返回 ("none", 0)。"""
    q = select(MembershipLedger).where(
        MembershipLedger.user_id == user_id,
        MembershipLedger.level.in_(["month", "year"]),
        MembershipLedger.action.in_(["grant", "rollback"]))
    rows = (await db.execute(q)).scalars().all()
    voided = {r.order_id for r in rows if r.action == "rollback"}
    grants = [r for r in rows
              if r.action == "grant" and r.order_id != exclude_order_id
              and r.order_id not in voided]
    grants.sort(key=lambda r: (r.created_at or datetime.max, r.id or 0))
    now = datetime.now()
    level = "none"
    expire_at = None
    for r in grants:
        d = r.grant_days or 0
        if d <= 0:
            continue
        level = r.level
        base = expire_at if (expire_at and expire_at > now) else (r.created_at or now)
        expire_at = base + timedelta(days=d)
    if not expire_at or expire_at <= now:
        return ("none", 0)
    return (level, (expire_at - now).days + 1)


async def expire_overdue_memberships(db: AsyncSession) -> int:
    """宽限期：把已过期且超过宽限期的会员 level 同步为 none。
    宽限期内（expire_at <= now < expire_at+72h）保留 level 与 continuous_flag，
    但 get_member_status 已按免费处理（is_vip=False），故此处只清理超宽限期的。
    """
    now = datetime.now()
    cutoff = now - timedelta(hours=settings.MEMBERSHIP_GRACE_HOURS)
    result = await db.execute(
        update(UserMembership)
        .where(UserMembership.level.in_(["month", "year"]),
               UserMembership.expire_at.isnot(None),
               UserMembership.expire_at <= cutoff)
        .values(level="none", expire_at=None, continuous_flag=0,
                bonus_quota=0, bonus_used=0))
    return result.rowcount or 0


# 会员规则展示字段的固定顺序与中文标题（前端按本表顺序渲染，缺失键自动跳过）。
MEMBERSHIP_RULE_LABELS = [
    ("tiers", "会员档位"), ("duration", "有效期"), ("grace", "宽限期"),
    ("quota", "额度规则"), ("upgrade", "升级顺延"), ("renew", "续费顺延"),
    ("continuous", "连续会员"), ("single_block", "单次购买"), ("refund", "退款规则"),
    ("disclaimer", "其他说明"),
]


async def build_membership_rules(db: Optional[AsyncSession] = None) -> dict:
    """构建《会员体系规则 V1.3》完整展示文案（第二十一~四十八条）。

    以 settings 为权威来源（保证任何环境下文案中的数值与实际生效规则一致，
    不依赖数据库是否已 seed）；若传入 db 且 system_configs 中存在 membership_rules（dict），
    则按键覆盖（运营可自定义文案，与 MySQL init.sql 的 distribution_rules 同一机制）。
    """
    q = settings.MEMBERSHIP_QUOTA
    mon = q.get("month", {})
    yr = q.get("year", {})
    life = q.get("lifetime", {})
    tier = settings.MEMBERSHIP_TIER_NAME
    rules = {
        "tiers": (f"三档会员：月会员·{tier.get('month', '基础')} / "
                  f"年会员·{tier.get('year', '标准')} / 终身会员·{tier.get('lifetime', '至尊')}"),
        "duration": (f"固定天数制（不自动续费）：月会员自开通起 {settings.MEMBERSHIP_MONTH_DAYS} 天、"
                     f"年会员 {settings.MEMBERSHIP_YEAR_DAYS} 天、终身会员于平台运营期内永久有效"),
        "grace": (f"到期后 {settings.MEMBERSHIP_GRACE_HOURS} 小时宽限期：宽限期内会员权益按免费用户处理，"
                  "仅保留「连续会员」身份标记；宽限期内续费在原到期时刻顺延并保留连续身份，"
                  "超宽限期未续费视为新购、连续标记清零"),
        "quota": ("周期总额度为全部会员工具共享总池："
                  f"月会员每 {mon.get('period_days', 30)} 天 {mon.get('period_total', 0)} 次、"
                  f"年会员每 {yr.get('period_days', 365)} 天 {yr.get('period_total', 0)} 次、"
                  f"终身会员每 {life.get('period_days', 365)} 天 {life.get('period_total', 0)} 次；"
                  f"单工具单日上限：月 {mon.get('daily_per_tool', 0)} 次 / 年 {yr.get('daily_per_tool', 0)} 次 / "
                  f"终身 {life.get('daily_per_tool', 0)} 次（每日 00:00 重置）；"
                  f"内容档案上限：月 {mon.get('archive_limit', 0)} 个 / 年 {yr.get('archive_limit', 0)} 个 / 终身不限；"
                  "赠送额度优先扣减，周期结束或会员到期时清零"),
        "upgrade": ("全价升级：支持月→年→终身逐级升级，升级按新档全价购买、不做差价折算；"
                    "旧档未用完的剩余整天叠加顺延到新档到期日（不浪费已付费时长）；"
                    "会员有效期内不可重复购买同档或更低档；宽限期内权益已失效，购买自当日重新起算；终身为最高档不可再升级"),
        "renew": ("续费顺延：会员未到期时续费同档，在原到期时刻顺延叠加；宽限期内续费恢复会员并保留连续身份；"
                  "超宽限期后续费按新购重新起算"),
        "continuous": ("连续会员：获得有效会员身份即记为「连续会员」；仅「超宽限期未续费」「退款」「管理员撤销」"
                       "三种情形会清零连续标记"),
        "single_block": ("会员有效期内已解锁全部完整内容，会员已覆盖的能力单次购买入口自动屏蔽，"
                         "无需重复付费；未纳入会员的能力仍可单独购买"),
        "refund": (f"会员为虚拟内容服务，支付后 {settings.REFUND_DAYS} 天内未使用可联系客服按退款规则处理；"
                   "退款按发放流水精确回收对应会员天数、清零赠送额度并收回连续标记；升级单退款恢复升级前旧卡剩余时长"),
        "disclaimer": "会员权益与规则以本页面展示为准；平台可在法律法规允许范围内调整规则并提前公示，调价不溯及已支付订单",
    }
    if db is not None:
        override = await get_config(db, "membership_rules", None)
        if isinstance(override, dict):
            for k, v in override.items():
                if isinstance(v, str) and v.strip():
                    rules[k] = v
    return rules
