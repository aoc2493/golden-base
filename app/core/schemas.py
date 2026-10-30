from pydantic import BaseModel, Field, field_validator
from typing import Optional, List, Any, Dict
import json


# ===== 文本字段内容校验 =====
# 地名与姓名等展示字段拒绝 HTML 敏感字符——不做完整字符白名单是为了
# 避免误伤真实地名（如带「·」的少数民族地名），正常文本绝不会出现尖括号与引号。
# 集合里刻意不含 & ：它既不能开启标签、也不能突破属性，前端 esc() 已把它转成实体，
# 而它在昵称/备注里是合法字符（如「Tom & Jerry」），一并禁掉属于过度收紧。
_MARKUP_CHARS = set('<>"\'`')


def _upload_allowed_hosts() -> set:
    """图片地址允许的域名白名单：配置的 CDN 域名 + COS 桶默认域名。

    上传接口返回两类地址：COS_CDN_DOMAIN 下的绝对 URL（配置时），或
    {bucket}.cos.{region}.myqcloud.com（未配置 CDN 时）。两者都必须放行，
    否则「未配 CDN」的部署会表现为上传成功、回写头像/反馈图却被判域名不受信任。
    只收录自家 COS 域名，不放宽任何外部来源。"""
    from app.config import settings
    allowed = set()
    host = (settings.COS_CDN_DOMAIN or "").strip().lower()
    if host.startswith(("http://", "https://")):
        host = host.split("/")[2] if "/" in host else host
    host = host.rstrip("/")
    if host:
        allowed.add(host)
    if settings.COS_BUCKET and settings.COS_REGION:
        allowed.add(f"{settings.COS_BUCKET}.cos.{settings.COS_REGION}.myqcloud.com".lower())
    return allowed


def _check_image_url(u, field_cn: str) -> str:
    """校验单个图片地址并归一：只接受站内单斜线绝对路径，或白名单域名的 http(s) 地址。

    反斜线必须显式拒绝：浏览器把 `/\\evil.com/x` 按 `//evil.com/x` 规范化，只判
    startswith("//") 会被绕过（存储型外链/追踪像素）。
    URL 的 host 用 urlsplit 取，不用字符串 split，避免 `host:port` / 大小写差异误判。
    """
    from urllib.parse import urlsplit

    if not isinstance(u, str):
        raise ValueError(f"{field_cn}格式非法")
    s = u.strip()
    if not s:
        raise ValueError(f"{field_cn}为空")
    if len(s) > 500:
        raise ValueError(f"{field_cn}过长")
    if any(ord(c) < 32 or ord(c) == 127 for c in s):
        raise ValueError(f"{field_cn}含非法字符")
    if "\\" in s:
        raise ValueError(f"{field_cn}协议非法")
    if s.startswith("//"):
        raise ValueError(f"{field_cn}协议非法")
    if s.startswith("/"):
        if ".." in s:
            raise ValueError(f"{field_cn}含非法路径")
        return s
    parsed = urlsplit(s)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError(f"{field_cn}协议非法")
    host = parsed.hostname.lower()
    allowed = _upload_allowed_hosts()
    if not allowed:
        raise ValueError(f"{field_cn}域名不受信任（未配置 COS）")
    if host not in allowed:
        raise ValueError(f"{field_cn}域名不受信任")
    return s


def _reject_markup(v, field_cn: str):
    """拒绝 HTML 敏感字符与控制字符；空白串归一为 None（可选字段语义）"""
    if v is None:
        return None
    if not isinstance(v, str):
        raise ValueError(f"{field_cn}格式非法")
    s = v.strip()
    if not s:
        return None
    if any(c in _MARKUP_CHARS for c in s):
        raise ValueError(f"{field_cn}含非法字符")
    if any(ord(c) < 32 or ord(c) == 127 for c in s):
        raise ValueError(f"{field_cn}含非法字符")
    return s


# ===== 认证 =====
class LoginRequest(BaseModel):
    code: str = Field(..., max_length=64, description="H5设备码，格式 h5-xxx")
    invite_code: Optional[str] = Field(None, max_length=12)

class EmailRegisterRequest(BaseModel):
    """Web 站邮箱注册"""
    email: str = Field(..., max_length=255, description="邮箱")
    password: str = Field(..., min_length=8, max_length=128, description="密码，至少 8 位")
    invite_code: Optional[str] = Field(None, max_length=32, description="邀请码（可选）")
    # 邮箱验证码：若服务端目前已为该邮箱下发过验证码，则必填且必须匹配（防批量注册/账号枚举）
    code: Optional[str] = Field(None, max_length=12, description="邮箱验证码（如已下发则必填）")


class SendEmailCodeRequest(BaseModel):
    """Web 站注册：下发邮箱验证码"""
    email: str = Field(..., max_length=255, description="邮箱")
    purpose: Optional[str] = Field("register", max_length=16, description="用途标识")


class EmailLoginRequest(BaseModel):
    """Web 站邮箱登录"""
    email: str = Field(..., max_length=255, description="邮箱")
    password: str = Field(..., min_length=1, max_length=128, description="密码")


class PasswordResetRequest(BaseModel):
    """密码重置申请（无邮件服务时转为人工工单）"""
    email: str = Field(..., max_length=255, description="注册邮箱")


class PasswordResetConfirmRequest(BaseModel):
    """使用邮件一次性验证码设置新密码。"""
    email: str = Field(..., max_length=255)
    code: str = Field(..., min_length=6, max_length=12)
    new_password: str = Field(..., min_length=8, max_length=128)


class WechatLoginRequest(BaseModel):
    code: str = Field(..., max_length=128)
    invite_code: Optional[str] = Field(None, max_length=12)
    state: Optional[str] = Field(None, max_length=256)
    # 双向定位：前端附带本地设备码（如有）。后端据此在微信首登时把微信标识
    # 并到既有设备账号而非新建，避免同一人两个 user_id 劈裂订单/开票。
    # 后端按 _DEVICE_CODE_RE 严格校验，非法值直接忽略，不作为信任输入。
    device_code: Optional[str] = Field(None, max_length=64)


class SyncWechatProfileRequest(BaseModel):
    """同步微信头像/昵称：snsapi_userinfo 授权回跳的 code（一次性）+ state（CSRF 绑定）"""
    code: str = Field(..., max_length=128)
    # 同步微信资料 CSRF：必须回传 profile-authorize-url 下发的 state，
    # 且其 nonce 要与发起浏览器 Cookie 匹配，否则拒绝——防「攻击者用自己的 code
    # 诱导受害者打开链接，把攻击者微信绑到受害者账号后走微信登录接管账号」。
    state: Optional[str] = Field(None, max_length=256)


class RefreshRequest(BaseModel):
    code: str = Field(..., max_length=64)


class BindInviteRequest(BaseModel):
    invite_code: str = Field(..., max_length=12)


class TouchRequest(BaseModel):
    """推广触达上报（公开端点 POST /api/distribution/touch）。

    访客点击专属链接/扫码进入落地页时调用一次，用于「90 天末次触达」归因：
    visitor_key 必须与后续注册用户的 device_code 一致才能完成归因。未注册访客没有
    device_code 时可不传（该次触达不参与归因，不影响直传邀请码那条主路径）。"""
    invite_code: str = Field(..., min_length=1, max_length=12)
    visitor_key: Optional[str] = Field(None, max_length=64)


# ===== 订单 =====
class OrderCreateRequest(BaseModel):
    sku_code: Optional[str] = Field(None, max_length=40)
    product_id: Optional[int] = None
    channel: Optional[str] = Field(None, pattern="^(wechat|alipay)$")
    result_ref_id: Optional[int] = None
    biz_data: Optional[Dict[str, Any]] = Field(None, description="业务快照")
    @field_validator("biz_data")
    @classmethod
    def _limit_biz_size(cls, v):
        # 限制 biz_data 序列化后不超过 4KB，防止超大 JSON 占库
        if v is not None and len(json.dumps(v, ensure_ascii=False)) > 4096:
            raise ValueError("业务参数过大")
        return v


class RefundRequest(BaseModel):
    order_id: int
    reason: str = Field(..., max_length=100)
    description: Optional[str] = Field(None, max_length=200)


# ===== 业务入参模型 =====
# 各业务能力的入参模型不在本文件：由插件 api 内的请求体 + 插件 service 的统一归一校验承接，
# 前置结果与报告端点均由插件提供
# （order.py 下单时从 biz_data 派生 biz_key 也同样调用插件的归一逻辑）。
# core 不预置任何业务专属入参模型，新增业务能力请在对应插件内定义。


# ===== 权益校验 =====
class EntitlementCheckRequest(BaseModel):
    # 收紧为「小写标识符 + 至多一个点分命名空间」（如 vip、demo.echo）：feature 直接进
    # 权益查询与配额 key，任意自造字符串会让脏值进入数据库查询。长度 20 与
    # user_entitlements.feature（VARCHAR(20)）对齐——超长值否则要到落库时才报错。
    # 点号是插件能力码的正式分隔符（manifest 里 code="demo.echo"），不能按变量的字符集排掉。
    feature: str = Field(..., max_length=20,
                         pattern=r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)?$")
    biz_key: Optional[str] = Field(None, max_length=64)
    # 双人能力的业务键由双方信息推导，前端算不出服务端的哈希，故上送原始信息由服务端派生，
    # 与运行期准备端点同一思路：键一律服务端重算，绝不采信前端传值。
    sides: Optional[List[Any]] = Field(None, description="双人能力时的双方信息，服务端据此派生 biz_key")
    relation: Optional[str] = Field(None, max_length=20)

    @field_validator("sides")
    @classmethod
    def _limit_sides(cls, v):
        # 与 OrderCreateRequest.biz_data 的 4KB 口径一致，防超大 JSON 白占带宽
        if v is not None and len(json.dumps(v, ensure_ascii=False)) > 4096:
            raise ValueError("双方信息过大")
        return v


# ===== 分销提现 =====
class WithdrawRequest(BaseModel):
    amount: float = Field(..., gt=0)
    channel: str = Field(..., pattern="^(alipay|wechat|bank)$")
    account_name: str = Field(..., min_length=1, max_length=50)
    account_no: str = Field(..., min_length=1, max_length=100)


# ===== 管理端 =====
class AdminAuditRequest(BaseModel):
    action: str = Field(..., pattern="^(paid|rejected)$")
    remark: Optional[str] = Field(None, max_length=200)
    # V1.3 第三十条失败返还：驳回时是否返还当日提现次数。True=非推广员原因(默认,返还)；False=违规冻结导致(不返还)
    refund_count: bool = Field(True, description="驳回时是否返还当日提现次数（违规冻结导致的驳回传 false）")
    operate_password: Optional[str] = Field(None, max_length=64, description="敏感操作二次密码")


class AdminRefundRequest(BaseModel):
    reason: str = Field(..., max_length=100)
    remark: Optional[str] = Field(None, max_length=200)
    operate_password: Optional[str] = Field(None, max_length=64, description="敏感操作二次密码")


class AdminMembershipRequest(BaseModel):
    action: str = Field(..., pattern="^(grant_month|grant_year|grant_lifetime|revoke)$")
    days: Optional[int] = Field(None, ge=1, le=3650)
    remark: Optional[str] = Field(None, max_length=200)
    operate_password: Optional[str] = Field(None, max_length=64, description="敏感操作二次密码")


class AdminPasswordResetRequest(BaseModel):
    new_password: str = Field(..., min_length=8, max_length=128)
    operate_password: Optional[str] = Field(None, max_length=64)


# 合规文书类型白名单（与 services/consent.CONSENT_ITEMS 一一对应）。
CONSENT_DOC_TYPES = ("^(privacy_policy|promoter_commitment|payment_disclaimer|rule_change"
                     ")$")


class ConsentSignRequest(BaseModel):
    """第十二/五十六/五条 + 合规文书主动勾选签署留痕（版本号/时间戳/IP/设备由服务端补齐）。"""
    doc_type: str = Field(..., pattern=CONSENT_DOC_TYPES)
    doc_version: Optional[str] = Field(None, max_length=20)
    agreed: bool = Field(True, description="实际提交的勾选值；默认不勾选由前端控制，服务端仅如实记录")
    order_id: Optional[int] = Field(None, description="支付前免责勾选关联的订单")
    # 是否为「隐私授权管理」页上用户明示的重新同意。不带本标记时，privacy_policy 的
    # 同意不得覆盖已撤回的状态（见 services/consent.sign）：支付弹层的「支付即代表同意」
    # 属默示同意，不能静默抹除用户的明示撤回。
    reaffirm: bool = Field(False, description="true=用户在授权管理页上明示重新同意")


class ConsentWithdrawRequest(BaseModel):
    """个保法第十五条：撤回同意。只需 doc_type：时间戳/IP/设备由服务端补齐（留痕
    不能交给客户端自述，否则可伪造）。可撤回范围由 services/consent.CONSENT_ITEMS 控制，
    不在这里再写一份白名单。"""
    doc_type: str = Field(..., pattern=CONSENT_DOC_TYPES)


# ===== 管理端违规处置、敏感词与排行结算 =====
class AdminViolationRequest(BaseModel):
    """第六十条：违规分级处置。minor警告整改/moderate冻结7天降级/severe永久清退/illegal涉嫌违法冻结。"""
    level: str = Field(..., pattern="^(minor|moderate|severe|illegal)$")
    reason: str = Field(..., min_length=1, max_length=500)
    order_id: Optional[int] = Field(None, description="涉违规订单（扣该订单佣金）")
    evidence: Optional[Dict[str, Any]] = None
    operate_password: Optional[str] = Field(None, max_length=64, description="敏感操作二次密码")

    @field_validator("evidence")
    @classmethod
    def _limit_evidence(cls, v):
        if v is not None and len(json.dumps(v, ensure_ascii=False)) > 4096:
            raise ValueError("证据信息过大")
        return v


class AdminUnfreezeRequest(BaseModel):
    """中度冻结解冻：force=True 为运营强制恢复（涉嫌违法核实无误/申诉成功）。"""
    force: bool = Field(False)
    operate_password: Optional[str] = Field(None, max_length=64, description="敏感操作二次密码")


class AdminLinkRequest(BaseModel):
    """第五十条/五十八条：断链（停用专属链接与二维码）或恢复。reenable=True 为恢复。"""
    reenable: bool = Field(False)
    reason: str = Field(..., min_length=1, max_length=500)
    operate_password: Optional[str] = Field(None, max_length=64, description="敏感操作二次密码")


class AdminSensitiveWordRequest(BaseModel):
    """第五十七/五十八条：敏感词维护（word 唯一）。level 1=一级拦截/2=二级预警。"""
    word: str = Field(..., min_length=1, max_length=50)
    level: int = Field(2, ge=1, le=2)
    category: Optional[str] = Field(None, max_length=50)
    enabled: int = Field(1, ge=0, le=1)
    operate_password: Optional[str] = Field(None, max_length=64, description="敏感操作二次密码")


class AdminRankSettleRequest(BaseModel):
    """第二十九条：手动触发月度结算（次月8号 cron 之外的补结算）。month 缺省为上一自然月。"""
    month: Optional[str] = Field(None, pattern=r"^\d{4}-\d{2}$", description="YYYY-MM，缺省=上月")
    operate_password: Optional[str] = Field(None, max_length=64, description="敏感操作二次密码")


# ===== 渠道对账差错台账 =====
class AdminReconcileResolveRequest(BaseModel):
    """对账差错人工处置。resolved=1 标记已处理（必须填写处置说明），=0 撤销标记。

    对账只发现不改账，差错的消除必须留下「谁、何时、怎么处理的」，否则事后无法回答
    「这笔资金差异到底平了没」——所以标记已处理时 note 必填。"""
    resolved: int = Field(..., ge=0, le=1)
    note: Optional[str] = Field(None, max_length=200, description="处置说明，标记已处理时必填")
    operate_password: Optional[str] = Field(None, max_length=64, description="敏感操作二次密码")


class AdminReconcileRunRequest(BaseModel):
    """手动触发对账（每日 cron 之外的补跑）。bill_date 缺省=回溯 RECONCILE_LOOKBACK_DAYS 天。

    补跑是幂等的：差错以 diff_key 唯一约束入库，重对同一天不会产生重复行。"""
    bill_date: Optional[str] = Field(None, pattern=r"^\d{4}-\d{2}-\d{2}$",
                                     description="YYYY-MM-DD，指定则只对该单日补跑")
    operate_password: Optional[str] = Field(None, max_length=64, description="敏感操作二次密码")


# ===== 敏感字段加密运维 =====
class AdminCryptoBackfillRequest(BaseModel):
    """把存量的明文敏感字段（提现实名/收款人姓名/收款账号）补加密。

    幂等：已带 enc:v1: 前缀的行跳过，重复调用不会双重加密。limit 限该次处理行数，
    分次跑完而不是一次扫全库：单次请求跑十分钟会撞上网关超时，而且把整库收款账号
    一次读进内存本身就是敏感信息的一次大面积暴露。"""
    limit: Optional[int] = Field(2000, ge=1, le=20000, description="该次最多处理的行数")
    operate_password: Optional[str] = Field(None, max_length=64, description="敏感操作二次密码")


class AdminAlertTestRequest(BaseModel):
    """向已配置的告警通道发一条测试消息。

    为何必须有这个入口：webhook 配错（复制时少了字符、钉钉安全设置选了关键词却没填
    「运行告警」、机器人被移出群）在配置那一刻不会报任何错，要等到真出故障时才发现
    一条也发不出去——而那正是告警通道唯一被验证的时刻，也是最坏的时刻。
    走二次密码：这是唯一能从管理端向平台之外的第三方群发消息的出口，与普通只读
    查询不同级；同时记审计日志，谁在什么时候发过测试消息可追溯。"""
    note: Optional[str] = Field(None, max_length=100, description="随测试消息附带的备注（如「上线前验证」）")
    operate_password: Optional[str] = Field(None, max_length=64, description="敏感操作二次密码")


class InvoiceApplyRequest(BaseModel):
    """电子发票申请。

    故意不收 amount 与 product_name：开票金额必须等于订单实付，两者一律从订单快照取
    （见 services/invoice.order_block）。前端能传金额就等于能开出金额不实的发票，
    那比不开票严重得多。
    也不收企业地址/电话/开户行/账号：电子普通发票用不上，而专票本项目不提供。
    """
    order_id: int = Field(..., ge=1, description="订单 ID")
    invoice_type: str = Field("personal", description="personal 个人/非企业单位，company 企业")
    title: str = Field(..., min_length=1, max_length=100, description="发票抬头")
    tax_no: Optional[str] = Field(None, max_length=30, description="纳税人识别号（企业必填）")
    email: str = Field(..., min_length=5, max_length=100, description="接收电子发票的邮箱")
    remark: Optional[str] = Field(None, max_length=200, description="备注")


class AdminInvoiceIssueRequest(BaseModel):
    """后台回填开具结果（人工在税局系统开完票后登记）。

    发票号码必填：台账上没有号码的「已开具」等于没开，事后无法向税务证明这张票存在。
    走二次密码 + 审计日志：写入的是对外具备法律效力的凭证信息。"""
    invoice_no: str = Field(..., min_length=1, max_length=60, description="发票号码")
    invoice_code: Optional[str] = Field(None, max_length=30, description="发票代码（数电票可空）")
    delivery: str = Field("email", description="交付方式 email/link/offline")
    invoice_file: Optional[str] = Field(None, max_length=500, description="版式文件地址（PDF/OFD）")
    operate_password: Optional[str] = Field(None, max_length=64, description="敏感操作二次密码")


class AdminInvoiceRejectRequest(BaseModel):
    """驳回开票申请。理由必填：用户有权知道为何不开，
    无理由驳回在用户看来与拒开发票没有区别（而拒开是《发票管理办法》第三十五条的罚则情形）。"""
    reason: str = Field(..., min_length=2, max_length=200, description="驳回理由（必填）")
    operate_password: Optional[str] = Field(None, max_length=64, description="敏感操作二次密码")


class AdminComplianceAssessmentRequest(BaseModel):
    """追加一条合规评估记录与意见（风险项的书面评估留存）。

    只追加、不改旧行：评估记录是证据，可编辑的证据没有证据价值——事后把「已整改」
    改成「一直合规」，就再也无法证明当时发现了什么、怎么改的。复核即新写一行，
    同一 risk_item 下以 id 最大的有效行为当前意见。

    measures 与 opinion 必填：只写「结论=已整改」而不写措施与理由，等于没有意见——
    行政检查要看的正是「依据什么得出这个结论」。"""
    risk_item: str = Field(..., min_length=1, max_length=20, description="风险清单编号，由运营方自定义")
    topic: str = Field(..., min_length=1, max_length=100, description="评估主题")
    scope_desc: Optional[str] = Field(None, max_length=2000, description="评估范围")
    legal_basis: Optional[str] = Field(None, max_length=300, description="法律依据条款")
    finding: Optional[str] = Field(None, max_length=4000, description="评估发现（整改前现状与风险定性）")
    conclusion: str = Field("rectified", pattern="^(rectified|acceptable|pending|rejected)$",
                            description="rectified已整改/acceptable风险可接受/pending待整改/rejected不采纳")
    measures: str = Field(..., min_length=1, max_length=4000, description="已采取的整改措施")
    opinion: str = Field(..., min_length=1, max_length=4000, description="合规意见正文（结论理由与残留风险）")
    assessor: Optional[str] = Field(None, max_length=50, description="评估人")
    next_review_at: Optional[str] = Field(None, pattern=r"^\d{4}-\d{2}-\d{2}$",
                                          description="下次复核日 YYYY-MM-DD")
    evidence: Optional[Dict[str, Any]] = None
    operate_password: Optional[str] = Field(None, max_length=64, description="敏感操作二次密码")

    @field_validator("risk_item", "topic")
    @classmethod
    def _v_required(cls, v, info):
        s = _reject_markup(v, info.field_name)
        # 必填项不能因「全是空白」被归一成 None：那会写进 NOT NULL 列，拖到落库时才报错
        if not s:
            raise ValueError(f"{info.field_name} 不能为空")
        return s.upper() if info.field_name == "risk_item" else s

    @field_validator("assessor", "legal_basis")
    @classmethod
    def _v_optional(cls, v, info):
        return _reject_markup(v, info.field_name)

    # scope_desc/finding/measures/opinion 是长文本，不走 _reject_markup：它一并禁掉换行与
    # 引号，而分段与「原文引用」在合规意见里是正当写法（与 AdminViolationRequest.reason、
    # FeedbackRequest.content 同一口径）。注入面在渲染侧关闭：后台面板对每个字段一律 esc()。

    @field_validator("measures", "opinion")
    @classmethod
    def _v_long_required(cls, v, info):
        # Field 的 min_length 拦不住「全是空格」，而一条只有空白的合规意见与没有意见等价：
        # 出具空壳记录比不出具更容易被认定为敷衍，故去首尾空白后为空即拒。
        s = (v or "").strip()
        if not s:
            raise ValueError(f"{info.field_name} 不能为空")
        return s

    @field_validator("scope_desc", "finding")
    @classmethod
    def _v_long_optional(cls, v):
        s = v.strip() if isinstance(v, str) else v
        return s or None

    @field_validator("evidence")
    @classmethod
    def _limit_evidence(cls, v):
        if v is not None and len(json.dumps(v, ensure_ascii=False)) > 4096:
            raise ValueError("佐证材料过大")
        return v


# ===== 用户（nickname 与数据库 VARCHAR(50) 对齐）=====
class UserUpdateRequest(BaseModel):
    nickname: Optional[str] = Field(None, max_length=50)
    avatar_url: Optional[str] = Field(None, max_length=500)

    @field_validator("nickname")
    @classmethod
    def _v_nickname(cls, v):
        # 昵称会在管理后台用户列表、分销团队等场景展示，同样拒绝 HTML 敏感字符
        return _reject_markup(v, "昵称")

    @field_validator("avatar_url")
    @classmethod
    def _v_avatar(cls, v):
        # avatar_url 应仅存放 /api/upload/avatar 返回的图片地址。只限长度、不限协议时
        # 可写入 javascript: / data:text/html 等伪协议（页面把它放进 <a href> 即成注入面），
        # 也可写入任意外站 URL 做跟踪像素/钓鱼。口径与反馈图共用 _check_image_url。
        if v is None:
            return None
        s = str(v).strip()
        if not s:
            return None
        return _check_image_url(s, "头像地址")


# ===== 反馈 =====
class FeedbackRequest(BaseModel):
    type: str = Field(..., pattern="^(功能问题|功能建议|其他)$")
    content: str = Field(..., max_length=500)
    images: Optional[List[str]] = Field(None, max_length=3)


    @field_validator("images")
    @classmethod
    def _limit_images(cls, v):
        # images 应仅存放 /api/upload/feedback 返回的图片地址：只限条数不校验地址，
        # 就能写入超长字符串占空间或任意协议地址（后台渲染即成注入面）。
        # 与 avatar_url 同口径，共用 _check_image_url。
        if v is None:
            return None
        return [_check_image_url(u, "图片地址") for u in v]


class GuestFeedbackRequest(BaseModel):
    """联系页在线留言（免登录，按 IP 限流）"""
    name: str = Field(..., min_length=1, max_length=50, description="姓名")
    contact: str = Field(..., min_length=3, max_length=100, description="联系方式（手机或邮箱）")
    content: str = Field(..., min_length=5, max_length=2000, description="留言内容")
