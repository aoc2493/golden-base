"""卡券（渠道批发卡密）服务 —— 接入算法类 H5 前端的版本

================= 接入时必须知道的三个关键点 =================

【一】本模块不定义任何业务模型，只新增 card_batches / card_codes 两张纯卡券表。
独立卡券系统自带 Order / UserMembership / MembershipLedger / UserEntitlement /
MembershipUsage 五个模型，与 H5 库里已有的同名表**口径不兼容**，直接并入会炸：
  · user_memberships：H5 的 bonus_quota / bonus_used / continuous_flag 是 NOT NULL，
    独立版模型没有这几列 → INSERT 直接 1364 缺列，会员根本发不出去；
  · 会员流水表名：独立版是复数 membership_ledgers，H5 是单数 membership_ledger
    → 流水分裂成两张表，日后回滚权益时找不到 grant 流水；
  · user_entitlements：独立版 feature varchar(40) / biz_key varchar(128)，
    H5 是 varchar(20) / varchar(64)，且 H5 的 order_id 为 NOT NULL；
  · 会员额度：独立版自建 membership_usages 计数，H5 是以 orders 表
    pay_channel='member' 的 0 元单计数（services/quota.py）→ 必然双算或漏算。
所以这里：单次卡 → entitlement.grant_entitlement；会员卡 → membership.grant_membership；
额度完全交给 H5 现有 quota.py。**卡券模块只负责「把权益发出去」，不接管消耗。**

【二】biz_key 延迟绑定 —— 这是接入最核心的一处冲突
H5 的单次权益是「一份业务结果一把钥匙」：check_feature 的查询条件是 `biz_key = ?`，
而 SQL 里 `NULL = 'x'` 恒为 UNKNOWN，所以以 biz_key=NULL 发放的权益**永远命中不了**。
可卡券天然是「先兑换、后选业务结果」，兑换那一刻不可能知道 biz_key。
若照搬独立版直接发 NULL：用户兑完卡会发现所有业务结果都打不开 —— 付款后无交付。
本模块的做法：兑换时以 biz_key=None 发放（pending 状态），由
entitlement.check_feature 在用户第一次真正打开某份业务结果时就地 CAS 绑定
（仅 biz_key IS NULL 时生效，并发下只有一条能绑成功），
绑定后与「当场购买」的权益完全等价，且一份业务结果只绑一次。

【三】不接入独立版的「核销」模型
独立版有 POST /feature/consume 把权益置为 used。H5 的 check_feature 只认
status='available'，一旦核销，用户再看自己**已生成的报告**都会被拒；
H5 的「一次性」语义是靠 biz_key 绑定 + 订单复用（插件的 _find_reusable_*）实现的，
根本不需要核销。强行接入等于让用户花钱后看不到自己买过的报告，故本模块
不提供 consume，消耗逻辑完全沿用 H5。
"""
import logging
import secrets
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Optional

from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import row_lock
from app.core.models import CardBatch, CardCode, Order, Product, UserEntitlement
from app.core.services import entitlement as ent_svc
from app.core.services import membership as membership_svc
from app.core.utils.payment import has_real_payment

logger = logging.getLogger(__name__)

# 卡券兑换生成的 0 元订单用独立支付渠道标识，与真实支付渠道隔离：
#   · services/reconcile.py 只按真实渠道（wechat/alipay）拉账单对账，
#     渠道为 'card' 的订单天然不会被扫进对账，不会产生「平台无此单」的差错；
#   · 掉单补偿、退款等只针对真实支付单的逻辑也不会误伤卡券单。
CARD_PAY_CHANNEL = "card"

CARD_STATUS_UNUSED = "unused"
CARD_STATUS_USED = "used"
CARD_STATUS_DISABLED = "disabled"
CARD_STATUS_DESTROYED = "destroyed"   # 退款销毁：仅购买凭证卡（source=purchase）可达
CARD_SOURCE_PURCHASE = "purchase"     # 支付订单自动发卡的来源标识（渠道批发为 batch）

# 可制卡档位（目录/兑换口径）：single 单次 / membership 会员 / timepass 时长卡
_CARD_CATALOG_TYPES = ("single", "membership", "timepass")
# 支付订单自动发卡仅认 single/membership——时长卡只能由管理后台手工生码
_CARD_PRODUCT_TYPES = ("single", "membership")
# 时长卡档位 -> 兑换后发放的畅用分钟数；重复兑换在剩余时长上顺延叠加。
# 单一事实来源由插件 manifest 声明、注册表聚合（撤销中间叠加段时也读同一份）。
def _timepass_minutes():
    from app.plugins import registry
    return registry.timepass_sku_minutes()

# 卡密字符集：剔除 0/O/1/I/2/Z/5/S/8/B 等易混字符，
# 降低用户手工誊录错误与客服成本。25 个字符 16 位 ≈ 2^74，不可枚举。
_CODE_ALPHABET = "ACDEFGHJKLMNPQRTUVWXY34679"
_CODE_LEN = 16
_CODE_GROUP = 4
# 单批生码上限（防一次点错造成几十万条脏数据 / 长时间锁表）
BATCH_MAX_COUNT = 5000
# 加固：单用户每日兑换上限。卡密本身 2^74 不可枚举，但一旦某个渠道批次整体泄露，
# 攻击者可拿到的码是「有限且已知」的；分钟级限流拦不住慢速兑换，日上限把
# 单账号一天的损失面封住，正常用户远达不到（触发即提示联系客服，可人工放行）。
REDEEM_DAILY_MAX = 20


class CardRedeemError(Exception):
    """可预期的兑换失败。

    persist=True 表示「本次失败同时需要保留一处状态变更」（过期卡自动作废）。
    路由层据此选择 commit 而不是 rollback —— 否则作废会被回滚掉，
    过期卡长期停留在 unused 并被导出到渠道继续售卖。
    """

    def __init__(self, msg: str, persist: bool = False):
        super().__init__(msg)
        self.msg = msg
        self.persist = persist


# ---------------- 卡密生成 / 规范化 ----------------

def _format_code(body: str) -> str:
    """按 4 位一组加连字符，便于人工誊录与客服核对。"""
    return "-".join(body[i:i + _CODE_GROUP]
                    for i in range(0, len(body), _CODE_GROUP))


def normalize_code(raw: str) -> str:
    """把用户输入规范化为与库中一致的形态。

    用户从微信、Excel、短信等各种渠道复制卡密，常带空格、全角、大小写混杂，
    这里统一去掉所有非字母数字字符后重新分组，保证能命中库里的规范码。
    """
    if not raw:
        return ""
    body = "".join(ch for ch in str(raw).upper() if ch.isascii() and ch.isalnum())
    if not body:
        return ""
    return _format_code(body)


def _gen_one_code() -> str:
    """生成单张卡密。

    必须用 secrets（密码学随机）而非 random：卡密本身就是可直接兑换的资产，
    可预测的伪随机序列等于送给攻击者一把遍历钥匙（独立版用的就是 secrets，此处保持）。
    """
    return _format_code("".join(secrets.choice(_CODE_ALPHABET)
                                for _ in range(_CODE_LEN)))


def _gen_no(prefix: str) -> str:
    """单号：前缀 + 秒级时间 + 密码学随机后缀。

    独立版是「微秒字符串截断到 17 位（精度仅 10ms）+ 6 位数字随机」，
    批量生码时同 10ms 内会撞 orders.order_no / card_batches.batch_no 唯一约束；
    改用 token_hex(4) 后碰撞概率可忽略，同时保持时间序可读。
    """
    return f"{prefix}{datetime.now().strftime('%y%m%d%H%M%S')}{secrets.token_hex(4).upper()}"


async def _gen_unique_codes(db: AsyncSession, count: int) -> list:
    """生成 count 个库内不冲突的卡密。

    一次 IN 批量查重：独立版逐个 candidate 打一条 SELECT，count=5000 时
    会向数据库打 5000 条查询。card_codes.uk_code 唯一约束仍是最终兜底。
    """
    picked: set = set()
    rounds = 0
    while len(picked) < count:
        candidates = {_gen_one_code() for _ in range(count - len(picked) + 16)}
        candidates -= picked
        if candidates:
            taken = set((await db.execute(
                select(CardCode.code).where(CardCode.code.in_(list(candidates)))
            )).scalars().all())
            picked |= (candidates - taken)
        rounds += 1
        if rounds > 20:
            raise CardRedeemError("卡密生成冲突过多，请重试")
    return list(picked)[:count]


# ---------------- SKU 目录（读 products 表，零硬编码） ----------------

async def load_sku_index(db: AsyncSession) -> dict:
    """SKU -> Product（仅上架商品）。

    独立卡券系统把 CARD_CATALOG 写死在 catalog.py 里，是一套与前端商品不一致的
    SKU 口径（易与 products 表漂移）。这里改为直接读 products 表：
    前端卖什么，卡券就能发什么，杜绝口径漂移。
    """
    rows = (await db.execute(
        select(Product).where(Product.enabled == 1))).scalars().all()
    return {p.sku_code: p for p in rows if p.sku_code}


def is_card_sku(prod: Optional[Product]) -> bool:
    """该商品是否可作为卡券发放。"""
    if not prod or not prod.sku_code:
        return False
    return (prod.product_type or "") in _CARD_CATALOG_TYPES


async def card_catalog(db: AsyncSession) -> list:
    """可制卡的 SKU 列表（后台下拉用）。"""
    idx = await load_sku_index(db)
    out = [{
        "sku_code": p.sku_code,
        "name": p.name,
        "price": str(p.price),
        "product_type": p.product_type,
        "feature": p.feature,
    } for p in idx.values() if is_card_sku(p)]
    out.sort(key=lambda x: x["sku_code"])
    return out


def mask_code(code: str) -> str:
    """卡密脱敏。卡密是可兑换凭据，明文下发即扩大泄露面（日志 / 网关缓存 / 前端存储）。"""
    if not code:
        return ""
    body = code.replace("-", "")
    if len(body) <= 8:
        return body[:2] + "*" * max(len(body) - 2, 0)
    return f"{body[:4]}****{body[-4:]}"


# ---------------- 后台：生码 ----------------

async def generate_batch(db: AsyncSession, sku_code: str, count: int,
                         created_by: Optional[str] = None,
                         remark: Optional[str] = None,
                         expire_days: Optional[int] = None) -> CardBatch:
    """批量生码。返回已 flush 的批次对象，明细由 list_batch_codes 读取。"""
    idx = await load_sku_index(db)
    prod = idx.get(sku_code)
    if not is_card_sku(prod):
        raise CardRedeemError("该商品不支持作为卡券发放，请检查商品是否上架或类型是否匹配")
    if count < 1 or count > BATCH_MAX_COUNT:
        raise CardRedeemError(f"单批生码数量需在 1~{BATCH_MAX_COUNT} 之间")

    expire_at = None
    if expire_days:
        if expire_days < 1 or expire_days > 3650:
            raise CardRedeemError("有效期天数需在 1~3650 之间")
        expire_at = datetime.now() + timedelta(days=expire_days)

    batch = CardBatch(
        batch_no=_gen_no("B"), sku_code=sku_code, total_count=count, used_count=0,
        remark=remark, expire_at=expire_at, created_by=created_by)
    db.add(batch)
    await db.flush()

    codes = await _gen_unique_codes(db, count)
    now = datetime.now()
    db.add_all([CardCode(code=c, sku_code=sku_code, batch_id=batch.id,
                         source="batch", status=CARD_STATUS_UNUSED,
                         expire_at=expire_at, created_at=now) for c in codes])
    await db.flush()
    logger.info(f"卡券生码 batch={batch.batch_no} sku={sku_code} count={count} by={created_by}")
    return batch


async def list_batch_codes(db: AsyncSession, batch_id: int) -> list:
    return (await db.execute(
        select(CardCode).where(CardCode.batch_id == batch_id)
        .order_by(CardCode.id.asc()))).scalars().all()


async def disable_code(db: AsyncSession, code_id: int) -> CardCode:
    """作废一张未使用卡。

    已使用的卡不可作废：那等于从用户手里单方面收回已购资产，需要独立的
    「权益收回」运营流程，不能在这里静默改状态糊过去。

    【为什么不用 db.get 后改属性】
    db.get 是普通读取，不加行锁，与 redeem 的 `SELECT ... FOR UPDATE` 并发时会交错：
    作废读到 status=unused → 兑换抢到锁、置 used、发权益并提交 → 作废随后拿内存里
    那份**过期**的 ORM 状态覆盖写回 disabled。结果是用户已拿到权益，卡却记为
    「未使用被作废」：既无法追溯是谁用了、批次 used_count 也少计一张。
    这里改为带 status 条件的**原子 CAS 更新**（`WHERE id=? AND status='unused'`）：
      · 抢在兑换前 → 卡置 disabled，兑换随后读到 disabled 直接拒绝；
      · 被兑换抢先 → CAS 影响 0 行，作废明确失败并提示刷新，绝不清空兑换痕迹。
    两种交错结果都自洽，且以数据库行为唯一裁判。
    """
    card = (await db.execute(
        select(CardCode).where(CardCode.id == code_id))).scalar_one_or_none()
    if not card:
        raise CardRedeemError("卡券不存在")
    if card.status == CARD_STATUS_DISABLED:
        raise CardRedeemError("该卡券已作废")

    moved = (await db.execute(
        update(CardCode)
        .where(CardCode.id == code_id, CardCode.status == CARD_STATUS_UNUSED)
        .values(status=CARD_STATUS_DISABLED))).rowcount
    if not moved:
        raise CardRedeemError("仅未使用的卡券可作废（该卡状态已变更，请刷新后重试）")
    # UPDATE 走的是 Core 语句，ORM 对象仍是事务开始时的旧快照，必须 refresh 再返回，
    # 否则路由层会把 status=unused 回给前端，运营以为没作废成功而重复点击。
    await db.flush()
    await db.refresh(card)
    return card


# ---------------- 用户端：兑换 ----------------

async def redeem(db: AsyncSession, raw_code: str, user_id: int) -> dict:
    """输码兑换：行锁取码 → 白名单校验 → 建 0 元订单 → 发权益 → 卡密置已用。

    并发安全：
      · row_lock(select ...) 对同一张卡密加行锁，配合「仅 unused 可兑换」的状态
        判定，同一张码并发提交只有一个能成功（防双花）；
      · card_codes.uk_code 唯一约束兜底重复发码。
    """
    code = normalize_code(raw_code)
    if not code or len(code.replace("-", "")) < 8:
        raise CardRedeemError("卡券码格式不正确，请核对后重试")
    if not user_id or int(user_id) <= 0:
        raise CardRedeemError("登录状态异常，请重新登录")

    # 加固：单用户每日兑换上限（见 REDEEM_DAILY_MAX 注释），封住泄露批次的损失面。
    # 只统计「渠道卡密兑换」(source != purchase)：支付订单自动发卡 auto_issue_for_order
    # 同样写 used_by / used_at / status=used，若一并计入，一个当天多次真实付费的用户
    # 会被自己买到的购买凭证卡挤占额度、反而兑不了线下渠道码。购买凭证卡从不导出、
    # 不是爆破面，本就不该消耗这个专为「泄露批次」设的配额。
    day_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    used_today = (await db.execute(
        select(func.count()).select_from(CardCode).where(
            CardCode.used_by == user_id,
            CardCode.used_at >= day_start,
            CardCode.source != CARD_SOURCE_PURCHASE))).scalar() or 0
    if int(used_today) >= REDEEM_DAILY_MAX:
        logger.warning(f"卡券兑换触达单日上限 user={user_id} used_today={used_today}")
        raise CardRedeemError("今日兑换次数已达上限，请明日再试或联系客服")

    card = (await db.execute(
        row_lock(select(CardCode).where(CardCode.code == code))
    )).scalar_one_or_none()
    # 以下失败分支对外文案统一为「卡券无效」。原来的
    # 细分文案（不存在/已兑换/已失效/已过期）等于向探测者免费提供状态 oracle：
    # 拿到部分泄露码的攻击者无需真正兑换即可零成本探明每张码的当前状态，
    # 进而筛出「unused=值得尝试、used=原码可能被渠道复投」的目标。卡密空间
    # 2^74 不可枚举 + user/IP 双限流已封死大规模爆破，此处消除的是剩余的
    # 零成本状态探测面。细分原因只写服务端日志（脱敏码），客服排查不受影响；
    # 过期卡的自动作废（persist=True 状态收敛）保持原样。
    INVALID_CODE_MSG = "卡券无效，请核对后重试或联系购买渠道"
    if not card:
        logger.warning(f"[兑换拒绝] 码不存在 user={user_id}")
        raise CardRedeemError(INVALID_CODE_MSG)
    if card.status == CARD_STATUS_USED:
        logger.warning(f"[兑换拒绝] 已兑换 user={user_id} code={mask_code(code)}")
        raise CardRedeemError(INVALID_CODE_MSG)
    # 白名单判定：只有 unused 可兑换。独立版是黑名单（仅拦 used/disabled），
    # 任何新增或异常状态值都会被当成可用卡直接发放权益。
    if card.status != CARD_STATUS_UNUSED:
        logger.warning(f"[兑换拒绝] 状态异常 status={card.status} "
                       f"user={user_id} code={mask_code(code)}")
        raise CardRedeemError(INVALID_CODE_MSG)
    if card.expire_at and card.expire_at <= datetime.now():
        card.status = CARD_STATUS_DISABLED
        logger.warning(f"[兑换拒绝] 已过期自动作废 user={user_id} code={mask_code(code)}")
        raise CardRedeemError(INVALID_CODE_MSG, persist=True)

    idx = await load_sku_index(db)
    prod = idx.get(card.sku_code)
    if not is_card_sku(prod):
        raise CardRedeemError("该卡券对应的商品已下架或不可用，请联系客服")

    # 会员卡降档前置校验，必须在建单/发放之前 —— 这样抛错时整笔兑换事务回滚，
    # 卡密仍是 unused（用户不会既丢档位又白扔一张卡）。
    # grant_membership 内的降档保护是兜底（它管的是「数据不被降档」），此处管的是
    # 「卡不被白白消耗」，两者缺一不可。
    if prod.product_type == "membership":
        block = await membership_svc.card_redeem_block_reason(db, user_id, prod.sku_code)
        if block:
            raise CardRedeemError(block)

    now = datetime.now()
    order = Order(
        order_no=_gen_no("CARD"),
        user_id=user_id,
        product_id=prod.id,
        sku_code=prod.sku_code,
        product_type=prod.product_type,
        product_name=prod.name,
        # 卡券已在线下/渠道完成收款，站内这张单只是权益载体，金额恒为 0。
        # 金额为 0 也意味着它不会进入任何退款/对账金额口径。
        amount=Decimal("0.00"),
        status="completed",
        pay_channel=CARD_PAY_CHANNEL,
        paid_at=now,
        fulfilled_at=now,
        biz_data={
            "card_id": card.id,
            "card_batch_id": card.batch_id,
            "card_masked": mask_code(card.code),
        },
    )
    db.add(order)
    await db.flush()

    feature = None
    tp_expire = None
    tp_stacked = False
    if prod.product_type == "membership":
        # 复用 H5 的会员发放：自动处理新购/续费/升级、写 membership_ledger 流水、
        # 重置本期额度。独立版自建的那套会因 NOT NULL 缺列直接失败。
        await membership_svc.grant_membership(
            db, user_id, prod.sku_code, order_no=order.order_no, order_id=order.id)
    elif prod.product_type == "timepass":
        # 时长卡：兑换即开通/顺延「限时畅用」权益，窗口内全功能不限次
        minutes = _timepass_minutes().get(prod.sku_code)
        if not minutes:
            raise CardRedeemError("该时长卡档位未配置时长，请联系客服")
        # 基准到期时刻 = 现有畅用权益里最晚的那个（无则从此刻起算）。
        # 并发兑换两张时长卡必须串行化，否则两个事务读到同一基准时刻、后提交覆盖
        # 先提交，用户凭空丢掉一张卡的时长 —— 故对命中的那一行加行锁。
        base_expire = await ent_svc.max_timepass_expire(db, user_id, now=now, for_update=True)
        tp_stacked = base_expire > now
        # 首兑与顺延都落一条**属于本单**的
        # 独立权益行。原实现顺延只改旧行，而旧行写死挂在**另一张卡的订单**上：
        #   ① 本兑换单名下没有任何权益行 → ent_svc.revoke_by_order(本单) 收不回，
        #      客服与审计也无法按订单核对这张卡究竟给了多少时长；
        #   ② 那张旧单一旦被回收，会连带收走后来叠加的全部时长（误伤后续兑换）；
        #   ③ 一切「按订单维度」的权益口径对本单都是盲区。
        # 独立成行后叠加语义完全不变（新行 = 旧到期时刻 + 本卡分钟数），但每段都能
        # 单独撤销：entitlement.revoke_timepass_by_order 会把其后各行整体前移。
        ent_new = UserEntitlement(
            user_id=user_id, sku_code=prod.sku_code,
            feature=ent_svc.TIMEPASS_FEATURE, status="available",
            order_id=order.id, biz_key=None,
            expire_at=base_expire + timedelta(minutes=minutes))
        db.add(ent_new)
        await db.flush()
        tp_expire = ent_new.expire_at
    else:
        # biz_key=None：等用户在 check_feature 里第一次打开某份业务结果时就地绑定。
        ent = await ent_svc.grant_entitlement(
            db, user_id, prod.sku_code, order.id, biz_key=None)
        feature = ent.feature

    card.status = CARD_STATUS_USED
    card.used_by = user_id
    card.used_at = now
    card.redeem_order_no = order.order_no
    if card.batch_id:
        await db.execute(
            update(CardBatch).where(CardBatch.id == card.batch_id)
            .values(used_count=CardBatch.used_count + 1))
    await db.flush()

    tip = None
    if tp_expire:
        tip = ("畅用时长已累加，" if tp_stacked else "畅用已开通，") + \
              f"{tp_expire.strftime('%m-%d %H:%M')} 前全站解读不限次使用"
    elif feature:
        # 会员有效期内兑换单次卡：权益不会作废，只是当期用不上（check_feature 会员直接放行）。
        # 明确告知，避免用户以为卡白买了。
        st = await membership_svc.get_member_status(db, user_id)
        if st.get("is_vip"):
            tip = "您当前是会员，该单次卡已存入账户，会员到期后可直接使用"

    logger.info(f"卡券兑换成功 code={mask_code(card.code)} user={user_id} "
                f"sku={prod.sku_code} order={order.order_no}")
    return {
        "sku_code": prod.sku_code,
        "name": prod.name,
        "product_type": prod.product_type,
        "feature": feature,
        "timepass_expire": tp_expire.strftime("%Y-%m-%d %H:%M") if tp_expire else None,
        # 单次卡需要用户去选一份业务结果才真正用上（延迟绑定）
        "need_choose_chart": feature is not None,
        "order_no": order.order_no,
        "tip": tip,
    }


async def my_cards(db: AsyncSession, user_id: int, page: int = 1,
                   page_size: int = 20) -> dict:
    """我的卡券（已兑换记录，卡密脱敏），分页返回。

    原实现写死 `limit=50` 并把「本页条数」当作 total 返回：一次兑 50 张以上的
    批发型用户看不到更早的记录，前端按 total 分页时也会因 total 恒等于本页条数
    而永远只有一页 —— 用户会认为卡券凭空丢失。
    这里返回真实总数，由路由层限制 page_size 上限。
    """
    page = max(int(page or 1), 1)
    page_size = max(min(int(page_size or 20), 100), 1)

    total = (await db.execute(
        select(func.count()).select_from(CardCode)
        .where(CardCode.used_by == user_id))).scalar() or 0
    rows = (await db.execute(
        select(CardCode).where(CardCode.used_by == user_id)
        .order_by(CardCode.id.desc())
        .offset((page - 1) * page_size).limit(page_size))).scalars().all()

    idx = await load_sku_index(db)
    out = []
    for c in rows:
        p = idx.get(c.sku_code)
        out.append({
            "code_masked": mask_code(c.code),
            "sku_code": c.sku_code,
            "name": p.name if p else c.sku_code,
            "used_at": c.used_at.strftime("%Y-%m-%d %H:%M") if c.used_at else None,
            # 卡券有效期（生码时设定，为空表示长期有效）：用户在「卡券兑换」页需要
            # 看到每张卡的时间，否则无从判断权益还剩多久。
            "expire_at": c.expire_at.strftime("%Y-%m-%d %H:%M") if c.expire_at else None,
        })
    return {"list": out, "total": total, "page": page, "page_size": page_size}


# ---------------- 支付订单自动发卡 / 退款销卡 ----------------

async def auto_issue_for_order(db: AsyncSession, order) -> Optional[CardCode]:
    """支付订单履约时自动生成对应档位的卡券，生成即自动使用（付款=买卡）。

    业务口径：站内所有真实付费（会员/单次解读）一律以卡券为权益凭证——用户在 H5
    付款成功后，系统即时生成一张对应 SKU 的卡券并立即自动使用（status 直接落
    used，used_by / redeem_order_no 回指支付订单），用户全程无感知。
    权益/会员的发放仍由 fulfillment.fulfill_paid_order 的既有分支完成，本函数只补
    「凭证」这一层：不改消耗链路，也不新建 0 元订单（那会污染订单口径与对账）。

    幂等：uk_card_source_order(source, source_order_no) 唯一约束 + SAVEPOINT 兜底。
    履约重试 / 回调重投时第二次插入触发 IntegrityError，被 SAVEPOINT 吞掉并返回
    None——既不重复发卡，也不会把调用方事务（订单置 completed 等）一并回滚。
    """
    if not order or not order.order_no or not order.sku_code:
        return None
    # 仅真实付费单发卡，判定与四条退款路径的 has_real_payment 完全统一：卡券兑换单（0 元权益载体）、会员免费解读单、历史 0 元/无资金渠道单
    # 都不是购买行为，再发一张等于凭空造资产。原实现手写渠道黑名单（card/member），
    # 漏掉金额<=0 等无真实资金流入的订单，且与退款资格口径漂移。
    if not has_real_payment(order):
        return None
    # 仅 single / membership 参与支付自动发卡；时长卡（timepass）按运营裁定只能
    # 由管理后台手工生码，任何支付/自动路径一律不生成（与 _CARD_CATALOG_TYPES
    # 的唯一差异就在这里，两处口径不得合并）。
    if (order.product_type or "") not in _CARD_PRODUCT_TYPES:
        return None
    now = datetime.now()
    try:
        async with db.begin_nested():
            card = CardCode(
                code=(await _gen_unique_codes(db, 1))[0],
                sku_code=order.sku_code,
                batch_id=None,
                source=CARD_SOURCE_PURCHASE,
                source_order_no=order.order_no,
                status=CARD_STATUS_USED,          # 生成即自动使用
                used_by=order.user_id,
                used_at=now,
                redeem_order_no=order.order_no,
                created_at=now,
            )
            db.add(card)
            await db.flush()
        logger.info(f"支付订单自动发卡 order={order.order_no} sku={order.sku_code} "
                    f"user={order.user_id} card={mask_code(card.code)}")
        return card
    except IntegrityError:
        logger.info(f"支付订单卡券已存在，幂等跳过 order={order.order_no}")
        return None


async def destroy_by_order(db: AsyncSession, order_no: str) -> int:
    """退款成功后销毁该支付订单自动生成的购买凭证卡（退款=销卡）。

    CAS：仅 status='used' 的 purchase 卡会被销毁（发卡即自动使用，正常即 used；
    已 destroyed 的行不再匹配，天然幂等）。销毁后的卡：
      · 不可能再被兑换（redeem 白名单只认 unused）；
      · 管理端不可再作废（disable_code 仅对 unused 生效）；
      · 用户端「我的卡券」仍保留该历史记录（used_by 不清），资金与凭证的生命周期可追溯。
    返回销毁条数（0 = 该订单没有购买凭证卡，或已销毁过）。
    """
    if not order_no:
        return 0
    res = await db.execute(
        update(CardCode)
        .where(CardCode.source == CARD_SOURCE_PURCHASE,
               CardCode.source_order_no == order_no,
               CardCode.status == CARD_STATUS_USED)
        .values(status=CARD_STATUS_DESTROYED))
    return res.rowcount or 0

