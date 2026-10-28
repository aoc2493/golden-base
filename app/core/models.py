from datetime import datetime

from sqlalchemy import Column, BigInteger, String, Text, Integer, SmallInteger, DateTime, JSON, DECIMAL, func, text, Index, UniqueConstraint
from app.core.database import Base

# L25：created_at / updated_at 必须同时给 Python 端 default 与 DB 端 server_default，
# 两者缺一不可，改动前请先读完本段。
#
# 只用 server_default=func.now() 时时间戳由数据库生成：SQLite 的 CURRENT_TIMESTAMP
# 恒为 UTC，MySQL 的 NOW() 取会话时区；而全库业务代码统一用 datetime.now()（本地时间）
# 做比较。基准一旦不一致（开发/测试的 SQLite 必然差 8 小时），所有「DB 时间戳 vs 本地
# 时间」的判据就会恒真或恒假。探针实测后果（UTC+8 环境）：
#   · scheduler.close_expired_orders —— 刚下单 0 秒的 pending 订单被判超时置 expired，
#     前端轮询到 expired 直接抛「订单已关闭」：用户付了钱却被告知订单没了，极易重复
#     下单重复付款（支付回调仍能把 expired 激活为 completed，钱不会丢，但体验与
#     重复扣款风险都是真实的）；
#   · order.continue_pay —— 同一判据恒真，N6「继续支付」永远回「订单已超时，请重新下单」；
#   · scheduler.auto_refund_failed_reports —— 报告刚 failed 0 秒即满足「超 10 分钟」，
#     立刻全额退款，注释声明的重试窗口形同虚设；
#   · 插件的报告自愈守卫 —— 刚建好的报告被判为「已卡死 8 小时」，老化限频完全失效，
#     只剩 Redis 锁；Redis 降级放行时前端每轮询一次就补触发一次付费的上游计算与
#     大模型调用。
# Python 端 default/onupdate 在 ORM 的 INSERT/UPDATE 中优先于 server_default，因此写入
# 的时间戳与业务代码同基准；保留 server_default 是为了不改既有 DDL —— 生产库由
# sql/init.sql 建表，运维手工 INSERT 也仍需列默认值兜底。
# datetime.now 是不带括号的 callable：写成 datetime.now() 会把进程启动时刻固化成常量。


class User(Base):
    __tablename__ = "users"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    device_code = Column(String(64), unique=True, nullable=True, comment="外部浏览器兜底设备码")
    oa_openid = Column(String(64), unique=True, nullable=True, comment="服务号网页授权openid")
    mp_openid = Column(String(64), unique=True, nullable=True, comment="小程序openid")
    unionid = Column(String(64), unique=True, nullable=True)
    email = Column(String(255), unique=True, nullable=True, comment="邮箱（Web 站注册登录）")
    password_hash = Column(String(255), nullable=True, comment="密码摘要，格式 pbkdf2_sha256$迭代$盐$摘要")
    phone = Column(String(20), nullable=True)
    nickname = Column(String(50), nullable=True)
    avatar_url = Column(String(500), nullable=True)
    status = Column(SmallInteger, default=1, comment="1正常 2已注销")
    # A8：账号持有人自报的公历出生日期，仅用于年龄门槛（未成年人禁充值）。
    # 存公历而不存历法类型：声明只收公历，农历自报年龄无法向监管复现。
    # 与业务档案里的 birth_date 不是一回事：后者是「解读对象」（可能是他人、可能是未成年人）。
    # 注销时随其他个人信息一并置空，声明行为本身由 compliance_consents 留痕保留。
    declared_birth_date = Column(String(20), nullable=True, comment="A8 自报公历出生日期（年龄门槛）")
    age_declared_at = Column(DateTime, nullable=True, comment="A8 成年声明时点")
    inviter_id = Column(BigInteger, nullable=True, comment="一级邀请人，仅绑定一次")
    invited_at = Column(DateTime, nullable=True)
    # 双向定位（属主决策）：内部自增 ID 与登录标识两个维度共同钉死用户唯一性。
    # 本两列记录「最近一次登录用的标识」，订单创建时快照进 orders.login_id_*，
    # 即使日后标识变更/账号合并，历史订单与开票仍能双向回溯核对。
    last_login_type = Column(String(16), nullable=True, comment="最近登录标识类型 device/oa_openid/mp_openid/unionid")
    last_login_value = Column(String(255), nullable=True, comment="最近登录标识值（邮箱可达 255，与 schemas 同宽）")
    created_at = Column(DateTime, default=datetime.now, server_default=func.now())


class UserIdentity(Base):
    """身份台账：登录标识 ↔ user_id 的双向唯一映射（双向定位的存储底座）。

    为何单独建表而不只靠 users 表四列：
    · 唯一约束落在 (id_type, id_value)：任何一个登录标识终生只归属一个 user_id，
      从数据库层杜绝「同一微信号/设备码挂到两个账号」导致订单/开票分裂；
    · user_id 反向可查该账号全部登录标识（含历史），注销归档/合并后仍可审计回溯；
    · last_login_at 记录活跃时间，客服/财务核对「下单时到底是谁登录的」有据可查。
    users 表四列仍是登录热路径（唯一索引直查），本表是台账与兜底校验源。"""
    __tablename__ = "user_identities"
    __table_args__ = (UniqueConstraint("id_type", "id_value", name="uk_identity_value"),)
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    user_id = Column(BigInteger, nullable=False, index=True)
    id_type = Column(String(16), nullable=False, comment="device/oa_openid/mp_openid/unionid")
    id_value = Column(String(64), nullable=False)
    first_seen_at = Column(DateTime, default=datetime.now, server_default=func.now())
    last_login_at = Column(DateTime, default=datetime.now, server_default=func.now(),
                           onupdate=datetime.now)


class ResultCache(Base):
    __tablename__ = "result_cache"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    user_id = Column(BigInteger, nullable=False)
    cache_key = Column(String(64), nullable=False)
    input_data = Column(JSON, nullable=False)
    result_data = Column(JSON, nullable=False)
    api_source = Column(String(32), default="internal", comment="结果来源标识，由插件侧自行约定")
    created_at = Column(DateTime, default=datetime.now, server_default=func.now())
    expire_at = Column(DateTime, nullable=False)

    # 本表补齐三种用途各自需要的索引（与 sql/init.sql 中的 DDL 一致）：
    #   (user_id, id)      历史记录按 user_id 过滤 + id 倒序，走索引可去掉 filesort
    #                      （每行含完整结果 JSON，filesort 极易撑爆 sort buffer）
    #   (expire_at)        过期清理任务按 expire_at 删除，无索引时为全表扫描
    #   (api_source, cache_key) 按来源与业务键检索
    __table_args__ = (
        Index("idx_rc_user_id", "user_id", "id"),
        Index("idx_rc_expire_at", "expire_at"),
        Index("idx_rc_source_key", "api_source", "cache_key"),
    )


class Favorite(Base):
    """用户收藏表：收藏任意业务条目（条目类型由插件登记）。

    删除语义：源条目被删除后，收藏仍保留——
    因此收藏行自带 title/sub 展示快照与 payload 业务快照，源被软删/
    物理缺失时收藏页仍能展示信息；源为软删（行保留）时仍可打开。"""
    __tablename__ = "favorites"
    # 同一条目每人只能收藏一次：唯一约束是「重复收藏」的唯一硬保证。
    # 缺它时双击/并发会写进两行，而 api/favorite.py 的查重用 scalar_one_or_none，
    # 读到两行即抛 MultipleResultsFound → 该条目此后每次收藏都 500。
    __table_args__ = (
        UniqueConstraint("user_id", "item_type", "item_id", name="uk_favorite_item"),
    )
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    user_id = Column(BigInteger, nullable=False)
    item_type = Column(String(16), nullable=False, comment="插件登记的收藏类型")
    item_id = Column(BigInteger, nullable=False, comment="业务条目 id 或订单 id")
    title = Column(String(100), nullable=True)
    sub = Column(String(200), nullable=True)
    payload = Column(JSON, nullable=True, comment="业务条目快照；订单类收藏为 NULL")
    created_at = Column(DateTime, default=datetime.now, server_default=func.now())


class Product(Base):
    __tablename__ = "products"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    sku_code = Column(String(40), unique=True, nullable=True)
    product_type = Column(String(20), default="report")
    feature = Column(String(20), nullable=True)
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    price = Column(DECIMAL(10, 2), nullable=False)
    modules = Column(JSON, nullable=True)
    refund_rule = Column(String(500), nullable=True)
    sort_order = Column(Integer, default=0)
    enabled = Column(SmallInteger, default=1)
    created_at = Column(DateTime, default=datetime.now, server_default=func.now())


class Order(Base):
    __tablename__ = "orders"
    __table_args__ = (
        # 用户侧「我的订单」与后台列表按 user_id 过滤；关单/查单/对账任务按
        # (status, created_at) 扫描。orders 是增长最快的一张表，缺索引即全表扫描。
        # user_id 与 created_at 合成一条：列表是 WHERE user_id=? ORDER BY created_at DESC
        # LIMIT n，单列 user_id 索引能定位但要回表再 filesort；复合索引按序直接取前 n 行。
        # 最左前缀仍是 user_id，所以只按 user_id 过滤的查询照用，无需再留单列索引。
        Index("ix_orders_user_created", "user_id", "created_at"),
        Index("ix_orders_status_created", "status", "created_at"),
    )
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    order_no = Column(String(32), unique=True, nullable=False)
    user_id = Column(BigInteger, nullable=False)
    product_id = Column(BigInteger, nullable=True)
    sku_code = Column(String(40), nullable=True, index=True)
    product_type = Column(String(20), nullable=True)
    product_name = Column(String(100), nullable=False)
    amount = Column(DECIMAL(10, 2), nullable=False)
    # v7：新增 refund_pending（退款处理中，允许重试），解决 N2 退款卡死
    status = Column(String(20), default="pending",
                    comment="pending/completed/refunded/refund_pending/expired/cancelled")
    pay_channel = Column(String(10), nullable=True)
    result_ref_id = Column(BigInteger, nullable=True)
    input_snapshot = Column(JSON, nullable=True)
    biz_data = Column(JSON, nullable=True)
    inviter_id = Column(BigInteger, nullable=True)
    # 双向定位快照：下单时刻的登录标识（类型+值），与 user_id 共同钉死买家身份。
    # 注销会清空 users 表身份列、账号合并会改映射，但订单/开票追踪不能随之失真，
    # 故在创建订单时把「当时登录的是哪个标识」固化下来，财务核对可双向回溯。
    login_id_type = Column(String(16), nullable=True, comment="下单时登录标识类型快照")
    login_id_value = Column(String(255), nullable=True, comment="下单时登录标识值快照（与 users.last_login_value 同宽）")
    paid_at = Column(DateTime, nullable=True)
    pay_url = Column(String(500), nullable=True)
    pay_trade_no = Column(String(64), nullable=True)
    fulfilled_at = Column(DateTime, nullable=True)
    fail_reason = Column(String(200), nullable=True, comment="支付/履约失败原因，便于排查")
    created_at = Column(DateTime, default=datetime.now, server_default=func.now())
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now,
                        server_default=func.now())


class UserMembership(Base):
    __tablename__ = "user_memberships"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    user_id = Column(BigInteger, unique=True, nullable=False, index=True)
    level = Column(String(20), default="none", comment="none/month/year/lifetime")
    start_at = Column(DateTime, nullable=True)
    expire_at = Column(DateTime, nullable=True)
    source_order_no = Column(String(32), nullable=True)
    # V1.3 额度/宽限/连续/版本（列定义见 init.sql）
    bonus_quota = Column(Integer, default=0, nullable=False, comment="赠送/补偿额度，优先扣减，周期/到期清零")
    bonus_used = Column(Integer, default=0, nullable=False, comment="本周期已用赠送额度")
    period_start = Column(DateTime, nullable=True, comment="当前额度周期起算（终身每365天滚动）")
    continuous_flag = Column(SmallInteger, default=0, nullable=False, comment="连续会员标记：宽限期内续费保留")
    rule_version = Column(String(20), nullable=True, comment="购买时确认的规则版本号")
    created_at = Column(DateTime, default=datetime.now, server_default=func.now())
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now,
                        server_default=func.now())


class MembershipLedger(Base):
    """会员发放/回滚流水（N4/M6）：每笔开通/续期/退款独立记录，退款时精确回滚对应批次"""
    __tablename__ = "membership_ledger"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    user_id = Column(BigInteger, nullable=False, index=True)
    order_id = Column(BigInteger, nullable=False)
    order_no = Column(String(32), nullable=False)
    level = Column(String(20), nullable=False, comment="month/year/lifetime")
    grant_days = Column(Integer, default=0, comment="本次发放天数，永久为0")
    action = Column(String(20), default="grant", comment="grant发放/rollback回滚/upgrade升级")
    created_at = Column(DateTime, default=datetime.now, server_default=func.now())


class UserEntitlement(Base):
    __tablename__ = "user_entitlements"
    # P3（#33 属主决策加 DB 唯一约束）：与 init.sql 同口径，
    # 同一订单同一 feature 仅一条权益，数据库层兜底幂等。
    __table_args__ = (UniqueConstraint("order_id", "feature", name="uk_order_feature"),)
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    user_id = Column(BigInteger, nullable=False, index=True)
    sku_code = Column(String(40), nullable=False)
    feature = Column(String(20), nullable=False, index=True)
    status = Column(String(20), default="available", comment="available/used/expired/revoked")
    order_id = Column(BigInteger, nullable=False, index=True)  # T9：加索引便于幂等校验
    biz_key = Column(String(64), nullable=True)
    expire_at = Column(DateTime, nullable=True)
    used_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.now, server_default=func.now())


class Report(Base):
    __tablename__ = "reports"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    order_id = Column(BigInteger, nullable=False, unique=True, comment="M10：一单一报告唯一约束")
    user_id = Column(BigInteger, nullable=False)
    title = Column(String(200), nullable=True)
    chapters = Column(JSON, nullable=True)
    # v7：新增 refunded（已退款）状态
    status = Column(String(20), default="generating", comment="generating/completed/failed/refunded")
    # A4：AI 生成合成内容标识元数据（见 utils/ai_mark.build_ai_meta）。
    # 必须落库而不是每次响应时现算：标识是「生成时」的事实（哪次生成、哪个模型、
    # 哪几章出自大模型），事后无从复现；且历史报告在本次改动之前生成，现算会把它们
    # 一律标成当前口径，与事实不符。接口下发时由 ai_mark.label_payload 展平，
    # 元数据缺失的老报告按「算法生成」兜底——宁可标注偏保守，也不出现无标识的页面。
    ai_meta = Column(JSON, nullable=True)
    viewed_at = Column(DateTime, nullable=True)
    retry_count = Column(SmallInteger, default=0)
    # v19：软删除（档案页「解读历史」隐藏）；订单/财务不受影响，收藏保留
    deleted_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.now, server_default=func.now())
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now,
                        server_default=func.now())


class AiGenerationLog(Base):
    """A4：生成合成内容的日志留存表（《标识办法》第十一条：不少于六个月）。

    存摘要而不存原文：提示词与生成内容里含用户姓名、出生信息等个人信息，原文全量留存
    400 天等于把敏感数据另存一份，与《个人信息保护法》最小必要原则冲突；而监管核查
    与侵权举证需要的是「什么时间、哪个模型、为谁、生成了哪条内容」这条可追溯链路，
    摘要（prompt_digest）已足以用同一输入复现比对。
    content_id 与 reports.ai_meta.ProduceID 同源，是内容到日志的唯一反查键。
    清理：tasks/scheduler.purge_ai_generation_logs 按 AI_MARK_RETENTION_DAYS 定期删除。
    """
    __tablename__ = "ai_generation_logs"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    content_id = Column(String(80), nullable=False, index=True, comment="内容编号 ProduceID")
    user_id = Column(BigInteger, nullable=True, index=True)
    order_id = Column(BigInteger, nullable=True)
    report_id = Column(BigInteger, nullable=True)
    scene = Column(String(32), nullable=True, comment="报告场景标识")
    ai = Column(SmallInteger, nullable=False, default=0, comment="1 生成式大模型产出/0 第三方算法计算")
    provider = Column(String(100), nullable=True, comment="服务提供者名称")
    model = Column(String(60), nullable=True, comment="大模型标识；算法产出时为空或上游接口名")
    prompt_digest = Column(String(64), nullable=True, comment="输入摘要 sha256 前 32 位")
    input_chars = Column(Integer, default=0, comment="输入字符数")
    output_chars = Column(Integer, default=0, comment="生成内容字符数")
    status = Column(String(20), default="success", comment="success 生成成功/failed 生成失败/fallback 触发降级文案")
    remark = Column(String(200), nullable=True)
    created_at = Column(DateTime, default=datetime.now, server_default=func.now(), index=True)


class Refund(Base):
    __tablename__ = "refunds"
    # L3：refund_no 唯一（与 init.sql 的 uk_refund_no 对齐）。防退款回调重复投递/重试重复插入落多行。
    __table_args__ = (UniqueConstraint("refund_no", name="uk_refund_no"),)
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    order_id = Column(BigInteger, nullable=False, index=True)
    user_id = Column(BigInteger, nullable=False)
    refund_no = Column(String(40), nullable=True, comment="商户退款单号（N2/H3，UUID 防碰撞）")
    reason = Column(String(100), nullable=False)
    description = Column(String(200), nullable=True)
    status = Column(String(20), default="pending_refund",
                    comment="pending_refund/refunded/failed/processing")
    retry_count = Column(SmallInteger, default=0)
    fail_reason = Column(String(200), nullable=True)
    created_at = Column(DateTime, default=datetime.now, server_default=func.now())
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now,
                        server_default=func.now())


class ReconciliationDiff(Base):
    """A3：渠道对账差错台账。每日把渠道账单与本地订单/退款逐笔轧账，只记差异、不自动改账。

    为何不自动平账：差异成因横跨「渠道跨日入账、退款回调丢失、金额被篡改、本地漏单、
    账单口径差异」，自动改账一旦判错方向就是真实的资金错误（多发货或少退款），风险远大于收益。
    所以本表只做「发现 + 留痕 + 人工处置」：处置动作走既有入口（补偿履约 / admin 强制退款），
    完成后在本表标记 resolved。
    diff_key 唯一：同一账单日重跑（补跑漏账、人工重对）不会产生重复差错行。
    """
    __tablename__ = "reconciliation_diffs"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    diff_key = Column(String(160), unique=True, nullable=False,
                      comment="幂等键：bill_date|channel|diff_type|单号")
    bill_date = Column(String(10), nullable=False, index=True, comment="渠道账单日 YYYY-MM-DD")
    channel = Column(String(10), nullable=False, comment="wechat/alipay")
    diff_type = Column(String(24), nullable=False, index=True,
                       comment="channel_only 渠道有本地无/local_only 本地有渠道无/"
                               "status_mismatch 状态不符/amount_mismatch 金额不符/"
                               "refund_local_missing 渠道已退款而本地未回收/bill_unavailable 账单拉取失败")
    order_no = Column(String(32), nullable=True, index=True)
    channel_trade_no = Column(String(64), nullable=True)
    channel_amount = Column(DECIMAL(12, 2), nullable=True)
    local_amount = Column(DECIMAL(12, 2), nullable=True)
    channel_status = Column(String(30), nullable=True)
    local_status = Column(String(20), nullable=True)
    detail = Column(String(500), nullable=True)
    resolved = Column(SmallInteger, nullable=False, default=0, server_default=text("0"),
                      comment="0未处理 1已人工处理")
    resolved_note = Column(String(200), nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.now, server_default=func.now())


class Feedback(Base):
    __tablename__ = "feedbacks"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    user_id = Column(BigInteger, nullable=False)
    type = Column(String(20), nullable=False)
    content = Column(Text, nullable=False)
    images = Column(JSON, nullable=True)
    status = Column(String(20), default="pending")
    created_at = Column(DateTime, default=datetime.now, server_default=func.now())


class SystemConfig(Base):
    __tablename__ = "system_configs"
    id = Column(Integer, primary_key=True, autoincrement=True)
    config_key = Column(String(50), unique=True, nullable=False)
    config_value = Column(JSON, nullable=False)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now,
                        server_default=func.now())


# ==================== 一级直推分销 ====================
class Distributor(Base):
    __tablename__ = "distributors"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    user_id = Column(BigInteger, unique=True, nullable=False, index=True)
    invite_code = Column(String(12), unique=True, nullable=False)
    # N5：注销时改为 0 冻结而非物理删除，保留佣金流水用于对账
    status = Column(SmallInteger, default=1, comment="0冻结/注销 1正常 2违规封禁")
    total_commission = Column(DECIMAL(12, 2), default=0)
    pending_commission = Column(DECIMAL(12, 2), default=0)
    available_commission = Column(DECIMAL(12, 2), default=0)
    withdrawn_commission = Column(DECIMAL(12, 2), default=0)
    # M24：已结算佣金被退款冲回、余额不足时形成的负债。只记不还——全库无自动补债逻辑，
    # 需人工对账追讨（后台推广员列表以「冲回欠款」展示）
    debt_commission = Column(DECIMAL(12, 2), default=0)
    invite_count = Column(Integer, default=0)
    # paid_count：历史口径「支付即计」，保留作存量对账；规则 V1.3 的晋升只认 verified_paid_count
    paid_count = Column(Integer, default=0)
    # ===== V1.3 三级等级 / 验证付费用户晋升 / 冻结与断链 =====
    level = Column(SmallInteger, default=0, comment="当前生效等级 0普通/1高级/2合伙人")
    verified_paid_count = Column(Integer, default=0, comment="累计验证付费用户数（过7天退款期、终身只计一次）")
    promo_baseline = Column(Integer, default=0, comment="降级重升基准：降级生效时点已用验证用户数，重升只认此后新增")
    next_level = Column(SmallInteger, nullable=True, comment="待生效等级（满足晋升条件、等次日0点生效）")
    next_level_at = Column(DateTime, nullable=True, comment="待生效等级的生效时刻=达标次日0点")
    level_updated_at = Column(DateTime, nullable=True, comment="最近一次等级变更时点")
    exam_passed = Column(SmallInteger, default=0, comment="是否通过合规入门考试（0未过/1已过）")
    consent_signed_at = Column(DateTime, nullable=True, comment="《合规推广承诺书》签署时点")
    # A6：提现实名 AES-256-GCM 加密落库（见 utils/crypto_field.py）。
    # 列宽按「接口允许的最坏明文」实测密文长度定，而不是按字符数估：字段不限字符集，
    # 50 个汉字是 150 字节，密文 = 前缀7 + base64(nonce12 + 150 + tag16) = 247 字符。
    # 原 180 是 ASCII 口径（同 50 字符只 111 长），MySQL 严格模式会报 1406 让整个提现
    # 事务失败，非严格模式静默截断——截断的密文永远解不开，收款人信息不可恢复。
    # 口径由 tests/test_crypto_field.py::test_worst_case_ciphertext_fits_the_column 钉住。
    real_name = Column(String(512), nullable=True, comment="提现实名（密文，风控比对收款人一致）")
    frozen_until = Column(DateTime, nullable=True, comment="违规冻结到期时点（中度冻结7天）；未到期为冻结态")
    link_disabled = Column(SmallInteger, default=0, comment="断链：1=专属链接/二维码停用，暂停新增归因绑定")
    created_at = Column(DateTime, default=datetime.now, server_default=func.now())


class CommissionLog(Base):
    __tablename__ = "commission_logs"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    distributor_id = Column(BigInteger, nullable=False, index=True)
    buyer_id = Column(BigInteger, nullable=False)
    order_id = Column(BigInteger, unique=True, nullable=False)
    order_no = Column(String(32), nullable=False)
    order_amount = Column(DECIMAL(10, 2), nullable=False)
    rate = Column(DECIMAL(5, 4), nullable=False, comment="M8：Float 改 DECIMAL 避免精度问题；V1.3=实际生效费率(base+uplift封顶后)")
    # ===== V1.3 计佣口径快照：单笔佣金=实付×(基础费率+月度阶梯上浮)，次月8号按最终档位重算补差 =====
    base_rate = Column(DECIMAL(5, 4), nullable=True, comment="下单时等级基础费率快照(0.30/0.40/0.50)")
    uplift_rate = Column(DECIMAL(5, 4), default=0, comment="结算当时适用的月度阶梯上浮，月度重算后更新为最终值")
    level_snapshot = Column(SmallInteger, nullable=True, comment="下单时推广员等级；升级前未结算订单仍按原等级")
    month = Column(String(7), nullable=True, index=True, comment="归属自然月 YYYY-MM（以支付成功时间为准）")
    amount = Column(DECIMAL(10, 2), nullable=False)
    status = Column(String(20), default="pending", comment="pending/settled/cancelled")
    settled_at = Column(DateTime, nullable=True)
    cancelled_at = Column(DateTime, nullable=True)
    remark = Column(String(200), nullable=True)
    created_at = Column(DateTime, default=datetime.now, server_default=func.now())


class CommissionFailLog(Base):
    """T5：计佣失败记录，定时任务重试，避免佣金静默丢失"""
    __tablename__ = "commission_fail_logs"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    order_id = Column(BigInteger, nullable=False, index=True)
    order_no = Column(String(32), nullable=False)
    fail_reason = Column(String(300), nullable=True)
    retry_count = Column(SmallInteger, default=0)
    status = Column(String(20), default="pending", comment="pending/success/abandoned")
    created_at = Column(DateTime, default=datetime.now, server_default=func.now())
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now,
                        server_default=func.now())


class Withdrawal(Base):
    __tablename__ = "withdrawals"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    withdraw_no = Column(String(32), unique=True, nullable=False)
    distributor_id = Column(BigInteger, nullable=False, index=True)
    user_id = Column(BigInteger, nullable=False)
    amount = Column(DECIMAL(10, 2), nullable=False, comment="提现申请总额（税前）")
    tax_amount = Column(DECIMAL(10, 2), default=0, comment="N10：代扣个税金额")
    actual_amount = Column(DECIMAL(10, 2), nullable=True, comment="税后实际打款金额")
    status = Column(String(20), default="auditing", comment="auditing/paid/rejected")
    channel = Column(String(10), nullable=False)
    # A6：收款人姓名与账号均属敏感个人信息（账号泄露即可直接造成资金损失），
    # AES-256-GCM 加密落库；展示一律走 mask_* 脱敏，只有后台提现详情（二次密码门禁）
    # 才解密明文供打款。列宽口径同 Distributor.real_name——按接口允许的最坏明文实测
    # 密文长度（姓名 50 汉字→247，账号 100 汉字→447），不是按字符数估。
    account_name = Column(String(512), nullable=False, comment="收款人姓名（密文）")
    account_no = Column(String(512), nullable=False, comment="收款账号（密文）")
    remark = Column(String(200), nullable=True)
    # V1.3 第三十条：非推广员原因失败返还当次次数（置 1 后不计入当日 2 次限额）；违规冻结导致的不返还
    count_refunded = Column(SmallInteger, default=0, comment="1=当次提现次数已返还，不占每日限额")
    fail_reason = Column(String(200), nullable=True, comment="失败/驳回原因，用于区分是否返还次数")
    audited_at = Column(DateTime, nullable=True)
    auditor = Column(String(50), nullable=True)
    created_at = Column(DateTime, default=datetime.now, server_default=func.now())


# ==================== 分销 V1.3 新增：归因 / 验证付费用户 / 月度结算 / 合规钩子 ====================
class AttributionTouch(Base):
    """第三十六条：推广触达记录。用户点击专属链接/扫码/海报进入即记一次触达；
    注册时在 90 天窗口内取「注册前最后一次有效触达」归因。visitor_key 为未注册访客标识
    （设备指纹/前端匿名ID/临时token），注册后回填 bound_user_id。"""
    __tablename__ = "attribution_touches"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    visitor_key = Column(String(64), nullable=False, index=True, comment="未注册访客标识（设备指纹/匿名ID）")
    invite_code = Column(String(12), nullable=False, index=True)
    distributor_id = Column(BigInteger, nullable=False, index=True)
    ip = Column(String(45), nullable=True)
    user_agent = Column(String(255), nullable=True)
    touched_at = Column(DateTime, default=datetime.now, server_default=func.now(), index=True)
    bound_user_id = Column(BigInteger, nullable=True, comment="该触达最终归因绑定的注册用户（归因后回填）")


class VerifiedPaidUser(Base):
    """第十七、三十五条：验证付费用户台账。buyer 终身只计一次（buyer_id 唯一）。
    status：0=首付已计待过退款期 / 1=已过7天退款期正式计入 / 2=退款回退（不再计数）。
    verify_at=首付+7天，到期由定时任务置 status=1 并累加 distributor.verified_paid_count。"""
    __tablename__ = "verified_paid_users"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    distributor_id = Column(BigInteger, nullable=False, index=True)
    buyer_id = Column(BigInteger, nullable=False, unique=True, comment="终身只计一次")
    first_order_id = Column(BigInteger, nullable=True)
    first_paid_at = Column(DateTime, nullable=True, comment="首次付费（支付成功）时点")
    verify_at = Column(DateTime, nullable=True, comment="过退款期时点=首付+7天")
    status = Column(SmallInteger, default=0, comment="0待过退款期/1已计入/2退款回退")
    created_at = Column(DateTime, default=datetime.now, server_default=func.now())
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now, server_default=func.now())


class MonthlyPerformance(Base):
    """第二十~二十九条：每推广员每自然月一条，承载月度推广总金额、最终阶梯档位、
    阶梯差额补发/追回、排行榜名次与奖金、及次月8号结算状态。
    total_amount 口径=名下订单当月支付成功实付之和扣退款（第六/二十条）。
    ladder_adjust/rank_reward/clawback 可正可负；settled=1 表示次月8号已结算入账。"""
    __tablename__ = "monthly_performances"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    distributor_id = Column(BigInteger, nullable=False, index=True)
    month = Column(String(7), nullable=False, comment="自然月 YYYY-MM")
    total_amount = Column(DECIMAL(12, 2), default=0, comment="月度推广总金额（支付成功扣退款）")
    ladder_uplift = Column(DECIMAL(5, 4), default=0, comment="最终阶梯档位上浮 0/0.05/0.10")
    ladder_adjust = Column(DECIMAL(12, 2), default=0, comment="阶梯差额补发（+）/降档追回（-），次月8号一次性")
    final_rank = Column(Integer, nullable=True, comment="最终名次（仅前20，未上榜为空；避开 MySQL 保留字 rank）")
    rank_reward = Column(DECIMAL(10, 2), default=0, comment="排行榜奖金（并列平分后实得）")
    clawback = Column(DECIMAL(12, 2), default=0, comment="结算后特殊退款导致不达档位/名次的追回（第三十四条第5款）")
    disqualified = Column(SmallInteger, default=0, comment="第六十条中度/重度：1=取消当月排行榜与阶梯奖励资格")
    settled = Column(SmallInteger, default=0, comment="0未结算/1已结算入账")
    settled_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.now, server_default=func.now())
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now, server_default=func.now())
    __table_args__ = (UniqueConstraint("distributor_id", "month", name="uq_perf_dist_month"),)


class ExamQuestion(Base):
    """第七条：合规入门考试题库（内容为第十章宣传红线）。满分100、每题按 score 计分。"""
    __tablename__ = "exam_questions"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    category = Column(String(50), nullable=True, comment="所属红线类别，如效果承诺/恐吓诱导/绝对化用语")
    content = Column(Text, nullable=False, comment="题干")
    options = Column(JSON, nullable=True, comment="选项数组")
    answer = Column(String(20), nullable=False, comment="正确答案（单选存选项标识，多选存逗号分隔）")
    qtype = Column(String(10), default="single", comment="single单选/multiple多选/judge判断")
    score = Column(Integer, default=5, comment="本题分值")
    sort_order = Column(Integer, default=0)
    enabled = Column(SmallInteger, default=1)
    created_at = Column(DateTime, default=datetime.now, server_default=func.now())


class ExamRecord(Base):
    """第七条/第五十九条：考试记录，留痕不少于3年。不限次数直至通过；违规重考两次未过保持冻结。"""
    __tablename__ = "exam_records"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    user_id = Column(BigInteger, nullable=False, index=True)
    distributor_id = Column(BigInteger, nullable=True, index=True)
    score = Column(Integer, default=0)
    passed = Column(SmallInteger, default=0, comment="1=达到及格分(80)")
    answers = Column(JSON, nullable=True, comment="作答快照")
    attempt_no = Column(Integer, default=1, comment="第几次尝试")
    created_at = Column(DateTime, default=datetime.now, server_default=func.now())


class ComplianceConsent(Base):
    """第十二、五十六、五十九条：合规留痕（不少于3年）。
    doc_type: promoter_commitment=《合规推广承诺书》 / payment_disclaimer=支付前免责勾选 / rule_change=规则重大不利变更单独确认。
    记录文本版本号、时间戳、IP/设备。"""
    __tablename__ = "compliance_consents"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    user_id = Column(BigInteger, nullable=False, index=True)
    distributor_id = Column(BigInteger, nullable=True, index=True)
    doc_type = Column(String(30), nullable=False, comment="promoter_commitment/payment_disclaimer/rule_change")
    doc_version = Column(String(20), nullable=True, comment="文本版本号")
    agreed = Column(SmallInteger, default=1, comment="1=主动勾选同意")
    order_id = Column(BigInteger, nullable=True, comment="支付前免责勾选关联的订单")
    ip = Column(String(45), nullable=True)
    user_agent = Column(String(255), nullable=True)
    agreed_at = Column(DateTime, default=datetime.now, server_default=func.now(), index=True)


class ComplianceAssessment(Base):
    """A7：上线风险项的合规评估记录与意见留存。

    整改代码之外为什么还要单独一张表：代码只能证明「改了」，证明不了「为什么这么改、
    依据哪一条、谁在何时评估过、结论是已整改还是风险可接受」。行政检查与纠纷中被要求
    出示的正是后者——一份能追溯到具体法条、具体措施、具体责任人与下次复核时点的书面意见。

    存 DB 而不是仓库里的 markdown：markdown 不进数据库备份、不随库迁移，也无法在后台按
    风险项检索并展示给运营人员；而评估意见的保存期限应当不短于其所证明的业务行为留痕期。

    risk_item 用清单编号（A2/A3/A7/B1…）作主检索键。同一风险项允许多次评估（复核即追加），
    故不加唯一约束；当前有效意见以同 risk_item 下 status=1 且 id 最大的一行为准。
    """
    __tablename__ = "compliance_assessments"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    risk_item = Column(String(20), nullable=False, index=True, comment="风险清单编号，如 A7")
    topic = Column(String(100), nullable=False, comment="评估主题，如「分销晋升口径」")
    scope_desc = Column(Text, nullable=True, comment="评估范围：涉及的模块/口径/页面")
    legal_basis = Column(String(300), nullable=True, comment="法律依据条款，如《禁止传销条例》第七条第(二)项")
    finding = Column(Text, nullable=True, comment="评估发现（整改前现状与风险定性）")
    conclusion = Column(String(20), default="rectified",
                        comment="rectified已整改/acceptable风险可接受/pending待整改/rejected不采纳")
    measures = Column(Text, nullable=True, comment="已采取的整改措施（改了什么口径、落在哪些接口与文件）")
    opinion = Column(Text, nullable=True, comment="合规意见正文（结论理由与残留风险）")
    assessor = Column(String(50), nullable=True, comment="评估人（admin/法务/外部律师）")
    assessed_at = Column(DateTime, default=datetime.now, server_default=func.now(), index=True)
    next_review_at = Column(DateTime, nullable=True, comment="下次复核时点（口径或法规变更时提前）")
    evidence = Column(JSON, nullable=True, comment="佐证材料（代码位置、规则版本号、公示与确认留痕口径）")
    status = Column(SmallInteger, default=1, comment="1有效 0已作废（被后续评估替代，不删行）")
    created_at = Column(DateTime, default=datetime.now, server_default=func.now())


class SensitiveWord(Base):
    """第五十七、五十八条：敏感词库。level 1=一级拦截词（直接禁止生成并告警）/ 2=二级预警词（首次警告）。"""
    __tablename__ = "sensitive_words"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    word = Column(String(50), nullable=False, unique=True)
    level = Column(SmallInteger, default=2, comment="1一级拦截/2二级预警")
    category = Column(String(50), nullable=True, comment="对应红线条款，如第四十条效果承诺")
    enabled = Column(SmallInteger, default=1)
    created_at = Column(DateTime, default=datetime.now, server_default=func.now())


class ExternalAccount(Base):
    """第五十条：外部推广账号报备。status 0待审/1通过/2拒绝；拒不报备按中度及以上违规。"""
    __tablename__ = "external_accounts"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    distributor_id = Column(BigInteger, nullable=False, index=True)
    user_id = Column(BigInteger, nullable=False)
    platform = Column(String(30), nullable=False, comment="抖音/快手/小红书/视频号/公众号/B站/微博等")
    account_name = Column(String(100), nullable=False)
    account_url = Column(String(255), nullable=True)
    status = Column(SmallInteger, default=0, comment="0待审/1通过/2拒绝")
    remark = Column(String(200), nullable=True)
    created_at = Column(DateTime, default=datetime.now, server_default=func.now())
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now, server_default=func.now())


class ReportTicket(Base):
    """第五十八条：用户举报工单，24小时内响应核查反馈。status 0待处理/1处理中/2已处置/3已驳回。"""
    __tablename__ = "report_tickets"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    reporter_id = Column(BigInteger, nullable=True, index=True, comment="举报人，可匿名")
    target_distributor_id = Column(BigInteger, nullable=True, index=True)
    target_type = Column(String(30), nullable=True, comment="distributor/content/order")
    content = Column(Text, nullable=False, comment="举报内容")
    evidence = Column(JSON, nullable=True, comment="证据（图片URL/链接/截图）")
    contact = Column(String(100), nullable=True, comment="举报人联系方式")
    status = Column(SmallInteger, default=0, comment="0待处理/1处理中/2已处置/3已驳回")
    handler = Column(String(50), nullable=True)
    handle_result = Column(String(500), nullable=True)
    responded_at = Column(DateTime, nullable=True, comment="首次响应时点（24h内）")
    created_at = Column(DateTime, default=datetime.now, server_default=func.now())
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now, server_default=func.now())


class ViolationRecord(Base):
    """第五十九/六十条：违规分级处置记录（留痕不少于3年，平台免责证据链）。
    level: minor轻度/moderate中度/severe重度/illegal涉嫌违法。一条记录=一次处置。"""
    __tablename__ = "violation_records"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    distributor_id = Column(BigInteger, nullable=False, index=True)
    user_id = Column(BigInteger, nullable=True, index=True)
    level = Column(String(12), nullable=False, comment="minor/moderate/severe/illegal")
    action = Column(String(30), nullable=True, comment="warn/freeze/terminate/exit 等处置措施")
    reason = Column(String(500), nullable=True, comment="判定情形（对应第六十条具体条款）")
    evidence = Column(JSON, nullable=True, comment="固定证据（截图/链接/举报ID/巡检记录）")
    order_id = Column(BigInteger, nullable=True, comment="涉违规订单（扣该订单佣金）")
    report_ticket_id = Column(BigInteger, nullable=True, comment="关联举报工单")
    frozen_until = Column(DateTime, nullable=True, comment="本次冻结到期时点（中度7天）")
    level_before = Column(SmallInteger, nullable=True, comment="降级前等级")
    level_after = Column(SmallInteger, nullable=True, comment="降级后等级")
    clawback_amount = Column(DECIMAL(12, 2), default=0, comment="本次扣除/追回金额")
    handler = Column(String(50), nullable=True, comment="处置人（admin/system）")
    status = Column(String(20), default="applied", comment="applied已处置/revoked已撤销（申诉成功）")
    created_at = Column(DateTime, default=datetime.now, server_default=func.now())


class AdminOperationLog(Base):
    """M18：管理后台敏感操作审计日志"""
    __tablename__ = "admin_operation_logs"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    action = Column(String(50), nullable=False, comment="refund/grant_membership/audit_withdrawal 等")
    target_type = Column(String(30), nullable=True, comment="order/user/withdrawal")
    target_id = Column(String(40), nullable=True)
    detail = Column(Text, nullable=True, comment="操作前后值快照 JSON")
    ip = Column(String(45), nullable=True)
    created_at = Column(DateTime, default=datetime.now, server_default=func.now())


class InvoiceRequest(Base):
    """B1：电子发票申请登记与开具台账。

    为何必须有：《发票管理办法》第十九条——从事经营活动的单位和个人对外发生经营业务
    收取款项，收款方应当向付款方开具发票；第三十五条对应当开具而未开具的设了罚则。
    用户索取发票是法定权利，不得以「虚拟商品」「报告已看过」为由拒开；不提供申请入口，
    用户只能走 12366 投诉，而这类投诉在应用商店与监管侧都是硬伤。

    为何只做「登记 + 台账」而不做自动开票：对接税控/电子发票服务商需要纳税人资质与
    服务商合同，不是代码能凭空补上的；但申请入口、抬头与税号采集、开具状态回写、
    驳回理由留痕可以先落地——人工在税局系统开完票后回填发票号码与交付方式即可。
    这张表就是「谁在什么时候申请了什么、平台何时开的、开的是哪一张」的唯一台账。

    一单一票：order_id 唯一约束。同一订单开两张发票属虚开；而并发双击提交若无唯一约束
    就会真的产生两行（SELECT 判重 → INSERT 在无锁下会被穿透，与 order.py 退款抢占同一个坑）。
    驳回/撤销后不新建行而是改本行：一单一票的约束不能松，但用户把抬头写错后必须能改。

    金额只从订单快照取，绝不接受前端传值：前端传来的金额一旦与实付不符，
    开出的就是金额不实的发票，那比不开票严重得多。

    刻意不采集企业地址/电话/开户行/账号：电子普通发票只需抬头 + 税号（企业）+ 邮箱，
    那四项只有专用发票才要，而专票需一般纳税人资质且本项目不涉。多采一项就多一项
    个人信息泄露面（《个保法》第六条最小必要）。
    """
    __tablename__ = "invoice_requests"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    apply_no = Column(String(32), unique=True, nullable=False, comment="申请单号 IV+时间戳+随机数")
    order_id = Column(BigInteger, unique=True, nullable=False, comment="一单一票（唯一约束防并发穿透与虚开）")
    order_no = Column(String(32), nullable=False, index=True)
    user_id = Column(BigInteger, nullable=False, index=True)
    amount = Column(DECIMAL(10, 2), nullable=False, comment="开票金额，取订单实付快照，不接受前端传值")
    product_name = Column(String(100), nullable=True, comment="商品名称快照（开票时参照）")
    invoice_type = Column(String(20), nullable=False, default="personal",
                          comment="personal 个人/非企业单位，company 企业（企业必填税号）")
    title = Column(String(200), nullable=False, comment="发票抬头：个人填姓名或「个人」，企业填营业执照全称")
    tax_no = Column(String(30), nullable=True, comment="纳税人识别号（企业必填，15~20 位）")
    email = Column(String(100), nullable=False, comment="电子发票接收邮箱（唯一交付通道，必填）")
    remark = Column(String(200), nullable=True, comment="用户备注")
    status = Column(String(20), nullable=False, default="pending", index=True,
                    comment="pending待开具/issued已开具/rejected已驳回/cancelled用户撤销")
    invoice_no = Column(String(60), nullable=True, comment="发票号码（开具后回填）")
    invoice_code = Column(String(30), nullable=True, comment="发票代码（数电票可为空）")
    item_name = Column(String(100), nullable=True, comment="开票项目名快照（当时生效的税收分类，事后改配置不影响已开的票）")
    issued_at = Column(DateTime, nullable=True, comment="开具时点")
    delivery = Column(String(20), nullable=True, comment="交付方式 email邮箱/link下载链接/offline线下")
    invoice_file = Column(String(500), nullable=True, comment="发票版式文件地址（PDF/OFD，走 COS）")
    reject_reason = Column(String(200), nullable=True, comment="驳回/作废理由（必填，用户有权知道为何不开）")
    need_red_flush = Column(SmallInteger, nullable=False, default=0, server_default=text("0"),
                            comment="1=已开票但订单随后退款，需红字发票冲销（退款钩子自动置位）")
    handler = Column(String(50), nullable=True, comment="开具/驳回操作人")
    created_at = Column(DateTime, default=datetime.now, server_default=func.now())
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now,
                        server_default=func.now())


# ============================================================
# 卡券模块（渠道批发卡密）—— 接入该业务 H5 时新增
#
# 只新增卡券自身必需的两张表；Order / UserMembership / UserEntitlement /
# MembershipLedger 等**一律复用本文件已有的模型**，不另定义 ——
# 独立卡券系统自带的那几套同名模型与本库口径不兼容：
#   · user_memberships 的 bonus_quota / bonus_used / continuous_flag 为 NOT NULL，
#     独立版模型缺列 → 写入直接 1364；
#   · 会员流水本库是单数 membership_ledger，独立版是复数 membership_ledgers；
#   · user_entitlements 本库 feature varchar(20)、biz_key varchar(64)、order_id NOT NULL。
# 详见 app/core/services/card.py 顶部说明。
# ============================================================


class CardBatch(Base):
    """卡券批次：渠道批发时一次生成一批，导出给渠道销售"""
    __tablename__ = "card_batches"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    batch_no = Column(String(32), unique=True, nullable=False)
    sku_code = Column(String(40), nullable=False, index=True)
    total_count = Column(Integer, default=0)
    used_count = Column(Integer, default=0)
    remark = Column(String(200), nullable=True)
    expire_at = Column(DateTime, nullable=True)
    created_by = Column(String(50), nullable=True)
    created_at = Column(DateTime, default=datetime.now, server_default=func.now())


class CardCode(Base):
    """卡券码：一码一用，兑换后发放对应 SKU 的权益/会员"""
    __tablename__ = "card_codes"
    __table_args__ = (
        # 同一来源订单只允许一条凭证（幂等兜底）。
        # MySQL 唯一索引允许多个 NULL，故不影响批次卡密（source_order_no 为 NULL）。
        UniqueConstraint("source", "source_order_no", name="uk_card_source_order"),
    )
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    code = Column(String(32), unique=True, nullable=False, index=True)
    sku_code = Column(String(40), nullable=False)
    batch_id = Column(BigInteger, nullable=True, index=True)
    source = Column(String(10), default="batch")
    source_order_no = Column(String(32), nullable=True)
    # 白名单状态机：unused 可兑换；used 已兑换；disabled 已作废/已过期
    status = Column(String(10), default="unused", index=True)
    used_by = Column(BigInteger, nullable=True, index=True)
    used_at = Column(DateTime, nullable=True)
    expire_at = Column(DateTime, nullable=True)
    redeem_order_no = Column(String(32), nullable=True)
    created_at = Column(DateTime, default=datetime.now, server_default=func.now())
