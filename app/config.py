import os
from pydantic_settings import BaseSettings
from typing import Optional

# .env 绝对路径（后端根目录），不受启动时 CWD 影响，保证凭证稳定加载
_ENV_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")

# 非生产环境白名单：只有明确声明为开发/测试/演示时才放宽安全红线。
# 判定必须反过来做——默认按生产处理：APP_ENV 一旦写成 prod / staging / Product 甚至拼错，
# 用 == "production" 的写法会把启动自检、CORS 放行、模拟支付拦截一起静默跳过。
NON_PROD_ENVS = ("development", "dev", "testing", "test", "demo", "local")


class Settings(BaseSettings):
    """应用配置，从环境变量读取（v7：补全限流/时区/管理二次验证等配置）"""
    # 服务
    APP_HOST: str = "0.0.0.0"
    APP_PORT: int = 8000
    APP_ENV: str = "production"
    # 应用展示名：用于告警消息等对外文案的署名。通用底座不预设任何产品名，
    # 部署方应配置成自己的主体名称（否则告警来源会显示成中性的「应用」）。
    APP_NAME: str = "Golden Base"
    # 时区：统一东八区，避免 datetime.now() 取到容器 UTC（T1）
    APP_TIMEZONE: str = "Asia/Shanghai"
    # 允许的前端来源（逗号分隔）；生产环境必须显式配置，一律不得放行 *（H5）
    CORS_ORIGINS: str = ""
    # 是否信任反向代理头（X-Real-IP / X-Forwarded-For）。
    # 默认 false：直连部署时这两个头完全由客户端控制，无条件信任会让
    # 所有 IP 维度防护（注册/下单/退款限流、管理令牌爆破锁定）被伪造头绕过。
    # 仅当确定部署在会覆写这些头的可信反代（如本仓库 nginx/nginx.conf）之后时才置 true。
    TRUST_PROXY_HEADERS: bool = False
    # ===== 内容安全策略 CSP =====
    # 前端无内联 <script>、无 on* 事件属性、无 eval/new Function，script-src 收紧为 'self'
    # 不影响任何现有功能，却能把“注入成功”降级为“注入不出可执行脚本”。
    # 注：docker 部署下静态页由 nginx 直接返回，本配置只作用于后端响应；
    # 生产环境需同时在 backend/nginx/nginx.conf 里加一致的 Content-Security-Policy。
    CSP_ENABLED: bool = True
    # style-src 必须保留 'unsafe-inline'：前端 innerHTML 生成的标记里有大量 style="..." 内联样式
    CSP_STYLE_SRC: str = "'self' 'unsafe-inline'"
    # img-src 必须包含 data:（主题/布局 CSS 用 data:image/svg+xml 做噪点与云纹背景）
    # 与 https:（头像/反馈图上传后返回的是 COS/CDN 绝对地址）
    CSP_IMG_SRC: str = "'self' data: blob: https:"
    # connect-src 默认同源（前端 js/api.js 的 API_BASE 为空）；跨域部署时改成后端地址
    CSP_CONNECT_SRC: str = "'self'"
    # 数据库
    # DB_TYPE: mysql（生产）/ sqlite（轻量部署与开发验证，免 MySQL 依赖）
    # 通用底座：以下默认值一律中性，不含任何垂直业务/产品名。
    # 存量部署若原先依赖代码默认值（未在 .env 显式配置 DB_NAME / DB_USER / DB_PASSWORD），
    # 升级后必须在 .env 里显式补回自己的库名与账号，否则会连不上库。
    DB_TYPE: str = "mysql"
    SQLITE_PATH: str = "app.db"
    DB_HOST: str = "localhost"
    DB_PORT: int = 3306
    DB_USER: str = "app"
    # 占位值，会命中启动自检的弱密码名单（生产阻断、非生产告警），强制运维显式配置
    DB_PASSWORD: str = "please-change"
    DB_NAME: str = "app_db"
    # Redis
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_PASSWORD: Optional[str] = None
    REDIS_DB: int = 0
    # Redis 连接/读写超时（秒），必须显式设上限：redis.from_url 默认 socket_connect_timeout=None，
    # Redis 宕机或未启动时，每个 redis_rate_limit / redis_acquire_lock 调用都会阻塞到操作系统
    # TCP 连接超时（本机实测 2~8 秒，IPv6 回退还会更久），把登录/下单/退款/上传等所有
    # 走限流的接口拖成“假死”。设小值后连接失败被快速抛出，交由 redis_rate_limit 的降级逻辑
    # （REDIS_FAIL_CLOSED）立即放行，请求不再卡住。生产 Redis 同机房毫秒级可达，2 秒足够宽裕。
    REDIS_SOCKET_TIMEOUT: float = 2.0
    # M2：Redis 故障降级策略。True=故障时拒绝放行（fail-closed：限流直接拦截、token 黑名单
    # 直接拒绝，代价是 Redis 宕机期间限流/黑名单转为整体不可用）；
    # False=故障时降级放行（保可用，代价是限流/注销黑名单在故障窗口内失效）。
    # 属主决策（本次）：安全优先，默认 True。注意「Redis 从未配置」（redis_client=None，
    # 如 sqlite 轻量/开发模式）不属于故障：各调用点对 None 单独放行，不受本开关影响。
    # 管理端令牌爆破锁定另有进程内计数双通道兜底，不受本开关影响。
    REDIS_FAIL_CLOSED: bool = True
    # M4：JWT httpOnly Cookie 的 SameSite 属性。同源部署（nginx 托管前后端）默认 lax 即可；
    # 仅当跨域部署（前端域名 ≠ API 域名）时必须置 none（且必须 HTTPS，否则浏览器丢弃 Secure Cookie）。
    AUTH_COOKIE_SAMESITE: str = "lax"
    # P2（代理头信任加固）：反代 → 后端的共享密钥。配置后 get_client_ip 额外要求
    # 请求头 X-Proxy-Auth 与之匹配才信任 X-Real-IP/XFF（防止同机进程直连 127.0.0.1:8000
    # 伪造 IP 绕过限流/爆破锁定）。需在宿主 nginx 的 /api 反代段加：
    #   proxy_set_header X-Proxy-Auth "同值";
    # 留空 = 不启用该校验（保持原行为）。
    PROXY_AUTH_SECRET: str = ""
    # 严格 IP 策略开关（默认关闭以保持可上线）：
    # 下面两项（管理 IP 白名单未配、信任反代头但未配共享密钥）此前一律只告警不阻断，
    # 原因写在 main.py 启动自检里——无固定办公出口 IP 的合法部署若强制白名单会「上线即起不来」，
    # 因此默认保持「最高级别告警」。置 True 后这两项在生产环境升级为**阻断项**（fail-closed），
    # 适合有固定出口 IP / 已接入堡垒机、且能接受配错即起不来的部署。
    SECURITY_STRICT_IP_POLICY: bool = False
    # 法定义务缺口的「本部署已逐项处置」确认位（默认 False = 生产环境拒绝启动）。
    # 背景：底座里有三项合规控制处于关闭状态——支付前免责勾选的服务端校验
    # （ENFORCE_PAYMENT_DISCLAIMER）、佣金提现代扣个税（WITHDRAW_TAX_ENABLED）、
    # 年龄门槛（minor_guard 按项目决策恒放行）。它们的默认关闭都有正当理由
    # （不阻断开箱即用的演示、重新开启需业务侧先接 UI），但「默认关闭」和「没人决定过」
    # 在日志里长得一模一样：启动自检每天响一次 ERROR，响到第 30 天就没人看了，
    # 于是一个从未被处置的法定义务缺口可以一路静默到真实用户面前。
    # 因此生产环境要求有人显式确认：COMPLIANCE_DECISIONS_ACK=true 表示「这三项我已逐条
    # 判断过本部署的处置」，确认后仍以 ERROR 级逐条留痕（不静默），但不再拦启动。
    # 非生产环境不受此约束——本地/演示链路必须能直接起。
    COMPLIANCE_DECISIONS_ACK: bool = False
    # JWT（H1：默认空值 fail-closed，任何环境未显式配置都会被启动自检拦截，不再放行已知默认密钥）
    JWT_SECRET_KEY: str = ""
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_DAYS: int = 7
    # M2（审计修复）：JWT 颁发/校验双重收紧，加 aud/iss 防止跨服务令牌混淆。
    # 长度给默认值不构成漏洞：仅校验 token 携带的 aud/iss 等于这两个常量。
    # 通用底座使用中性标识。注意：存量部署若未在 .env 显式配置，
    # 升级后新签发的令牌 aud/iss 会变化，旧令牌将校验失败（需重新登录）。
    JWT_AUDIENCE: str = "app-web"
    JWT_ISSUER: str = "app-backend"
    # A6：敏感字段（提现实名/收款人姓名/收款账号）落库加密密钥，见 utils/crypto_field.py。
    # 与 JWT 同一哲学：fail-closed，未配置或仍用占位值一律阻断启动。密钥一旦上线不得更换：
    # 换了之后已入库的密文全部解不开（收款账号再也读不出来，打款链路断）。
    # 生成：openssl rand -hex 32（四个 worker 必须共用同一把，不得进程内自生）。
    SENSITIVE_FIELD_KEY: str = ""
    # 微信支付
    WECHAT_MCH_ID: str = ""
    WECHAT_APP_ID: str = ""
    WECHAT_API_V3_KEY: str = ""
    WECHAT_CERT_SERIAL_NO: str = ""
    WECHAT_PRIVATE_KEY_PATH: str = "/app/certs/wechat_apiclient_key.pem"
    WECHAT_NOTIFY_URL: str = ""
    # 回调验签凭据二选一（微信支付 APIv3 两种模式，见 utils/payment.verify_callback）：
    #   · WECHAT_PUBLIC_KEY_PATH  —— 微信支付公钥模式（官方推荐）：回调头 Wechatpay-Serial
    #     为公钥ID（PUB_KEY_ID_ 开头），公钥本身不会过期，无需 5 年轮换平台证书。
    #   · WECHAT_PLATFORM_CERT_PATH —— 平台证书模式（兼容旧接入）：Serial 为 40 位 hex。
    # 两者都配时按回调头自动选择；都缺则回调一律拒绝（503）。
    WECHAT_PLATFORM_CERT_PATH: str = ""
    WECHAT_PUBLIC_KEY_PATH: str = ""
    # 微信服务号网页静默授权
    WECHAT_OA_APP_ID: str = ""
    WECHAT_OA_APP_SECRET: str = ""
    WECHAT_OAUTH_REDIRECT: str = ""
    # 支付宝
    ALIPAY_APP_ID: str = ""
    ALIPAY_PRIVATE_KEY_PATH: str = "/app/certs/alipay_private_key.pem"
    ALIPAY_PUBLIC_KEY_PATH: str = "/app/certs/alipay_public_key.pem"
    ALIPAY_NOTIFY_URL: str = ""
    ALIPAY_RETURN_URL: str = ""
    ALIPAY_GATEWAY: str = "https://openapi.alipay.com/gateway.do"
    # 本地演示用模拟支付（无任何真实渠道时走通下单→支付→履约全链路）。
    # 仅在非生产环境允许开启；APP_ENV 为生产时启动自检直接拒绝，端点本身也会 403。
    PAYMENT_MOCK: bool = False
    # 腾讯云 COS
    COS_SECRET_ID: str = ""
    COS_SECRET_KEY: str = ""
    COS_REGION: str = "ap-guangzhou"
    COS_BUCKET: str = ""
    COS_CDN_DOMAIN: str = ""
    # 腾讯云短信 SMS
    # 【未接线·全库无任何消费方】手机号验证码登录未建。下面五项只存于配置：既无短信
    # 客户端、也无发送/校验端点，前端也没有手机号登录入口（web/ 里的 phone 只出现在
    # 后台搜索框占位符与用户列表展示）。users.phone 列同样从未被写入过真实值
    # （全库只有注销时置 None 一处）。按本次清理口径，未建成的计划功能只标记不删；
    # 若确定不做手机号登录，这五项连同 users.phone 列、后台的用户搜索与展示可一并下掉。
    TENCENT_SMS_SECRET_ID: str = ""
    TENCENT_SMS_SECRET_KEY: str = ""
    TENCENT_SMS_SDK_APP_ID: str = ""
    TENCENT_SMS_SIGN_NAME: str = ""
    TENCENT_SMS_TEMPLATE_ID: str = ""
    # 业务
    # 【未接线·core 不消费这两个键】结果缓存的「复用判定」属第三方调用策略，只有真正调
    # 外部接口的业务插件才有权决定同参数是否复用；core 侧只做两件与它们无关的事：
    # tasks/scheduler.py 按 result_cache.expire_at 清理过期行、api/user.py 随账号注销删除。
    # 待接线说明：插件若需要统一的复用口径，应在此接入点读取本开关并写 expire_at，
    # 否则不要依赖它们——现在改这两个值不改变任何行为。
    RESULT_CACHE_ENABLED: bool = True
    RESULT_CACHE_DAYS: int = 30
    ORDER_TIMEOUT_MINUTES: int = 30
    REFUND_DAYS: int = 7
    # ===== A2 支付主动查单 / 掉单补偿 =====
    # 履约原本只有一条路径：等平台异步回调。回调会因网络闪断、发布重启、平台重试耗尽而
    # 全部丢失，此时用户已扣款而订单永久停在 pending/expired（掉单）。以下为拉取式兜底参数。
    PAY_QUERY_ENABLED: bool = True             # 总开关（渠道未配置时自动跳过，不报错）
    PAY_QUERY_DELAY_SECONDS: int = 20          # 下单后多久才允许主动查单：给异步回调让路，避免与回调抢同一笔单
    PAY_QUERY_PENDING_WINDOW_HOURS: int = 2    # pending 订单的查单回溯窗口（超时后由关单任务置 expired）
    PAY_QUERY_EXPIRED_WINDOW_HOURS: int = 48   # expired 订单的补偿窗口：回调全丢时用户其实已付款，_mark_order_paid 允许 expired→completed
    PAY_QUERY_BATCH_SIZE: int = 50             # 单轮最多查多少笔，防止把渠道查单接口打出限流
    PAY_STATUS_QUERY_COOLDOWN: int = 10        # 前端轮询 pay-status 触发查单的冷却秒数（同一订单，Redis SETNX）
    # ===== A3 每日渠道对账 =====
    # 对账是资金系统的最后一道防线：回调与查单都可能漏，只有拿渠道账单逐笔轧账，才能发现
    # 「渠道已收款而本地无单/状态不符/金额不符」与「渠道已退款而本地未回收权益」。
    RECONCILE_ENABLED: bool = True
    RECONCILE_HOUR: int = 10                   # 微信次日 09:00 生成前一日账单，官方建议 10:00 后拉取
    RECONCILE_LOOKBACK_DAYS: int = 3           # 每轮回溯天数（补跑漏账）；微信账单仅可下载 3 个月内
    RECONCILE_BILL_TYPE: str = "ALL"           # 微信账单类型：ALL 含当日支付成功单与发起成功的退款单
    # ===== A4 AI 生成合成内容标识 =====
    # 依据《人工智能生成合成内容标识办法》（2025-09-01 施行）与 GB 45438-2025：
    # 大模型产出的内容必须同时具备三项——① 显式标识（界面可感知的「AI 生成」提示）；
    # ② 隐式标识（随内容的元数据：内容属性/服务提供者名称或编码/内容编号）；③ 生成日志
    # 留存不少于 6 个月。缺任一项都属违规，且这三项是接入商核查与监管抽查时直接调阅的材料。
    AI_MARK_ENABLED: bool = True
    # 服务提供者名称必须为真实的备案/经营主体，底座不预设任何产品名。
    # 留空时生产环境会被启动自检阻断——标识与实际提供者不符本身即违规。
    AI_MARK_PROVIDER_NAME: str = ""
    AI_MARK_PROVIDER_CODE: str = ""              # 服务提供者编码：上线前填统一社会信用代码；留空则用下方域名派生
    AI_MARK_SITE_CODE: str = ""                  # 编码留空时的派生源，建议填 ICP 备案主体域名标识
    AI_MARK_RETENTION_DAYS: int = 400            # 生成日志留存天数：法规下限 180 天，留余量应对追溯与诉讼
    # ===== B2 告警通道（企业微信 / 钉钉群机器人） =====
    # 全库已有大量 logger.error 形式的告警留痕（[退款告警]/[计佣告警]/[掉单补偿告警]/对账差错/启动自检），
    # 但没有任何一条会主动推给人：日志躺在容器 stdout 里，没人看就等于没发生。
    # 资金类故障的发现时延直接等于资损金额，故必须把已有 ERROR 接到即时通道上。
    # 接入方式是一个 logging Handler（见 utils/alert.py install_alert_handler），而不是在各调用点
    # 逐个补发送：散在调用点上必然漏（新增一处 logger.error 就得记得补一次），
    # 而漏掉的那一处往往正是最严重的那个（退款重试耗尽、金额与渠道不符）。
    ALERT_ENABLED: bool = True                 # 总开关；未配任何 webhook 时自动不生效（只打一条 INFO）
    ALERT_WECOM_WEBHOOK: str = ""              # 企业微信群机器人 key=... 完整地址
    ALERT_DINGTALK_WEBHOOK: str = ""           # 钉钉群机器人 access_token=... 完整地址
    ALERT_DINGTALK_SECRET: str = ""            # 钉钉机器人「加签」密钥（SEC 开头）；安全设置选加签时必填
    ALERT_LEVEL: str = "ERROR"                 # 触发告警的最低日志级别（ERROR/CRITICAL）
    # 同类告警去重窗口（秒）。同一次故障往往在每轮调度里各刷一条（退款重试每 30 分钟一轮），
    # 不去重就会在几分钟内打满机器人配额（企微/钉钉均为 20 条/分钟，超限封禁 10 分钟）——
    # 结果是真正的新故障反而发不出去。窗口内被抑制的条数会累计，随下一条告警一起带出。
    ALERT_DEDUP_SECONDS: int = 600
    ALERT_MAX_PER_MINUTE: int = 10             # 全局风暴闸：一分钟内最多发多少条（低于平台 20 条硬限）
    ALERT_DETAIL_MAX_CHARS: int = 900          # 详情截断长度：异常栈动辄上千字，全文外发既超消息体也无从阅读
    ALERT_ENV_TAG: str = ""                    # 消息前缀环境标识；留空自动取 APP_ENV（多环境共用一个群时必填）
    # 每日心跳：沉默不等于健康。机器人被移出群、钉钉关键词改错、webhook 过期时，
    # 表现都是「一条告警也没有」，与「系统正常」完全同形——运维无从分辨，
    # 直到真出故障时才发现通道早就断了。每天固定发一条带统计的心跳，
    # 超过 24 小时没收到即可判定通道已断（心跳本身也走同一个 _post，
    # 所以它能验到的就是真故障时能不能发出去）。
    ALERT_HEARTBEAT_ENABLED: bool = True
    ALERT_HEARTBEAT_HOUR: int = 9              # 每日几点发（整点，东八区）
    # ===== B1 电子发票（申请登记 + 开具台账） =====
    # 《发票管理办法》第十九条：收取款项应当向付款方开具发票。用户索取发票是法定权利，
    # 所以入口默认开启；真要临时停（如税控盘更换期间）也必须在页面上说明并给客服路径，
    # 静默关掉等于拒开（第三十五条对应当开具而未开具的设了罚则）。
    INVOICE_ENABLED: bool = True               # 入口总开关；DB 的 invoice_enabled 可临时覆盖（与 refund_enabled 同范式）
    # 自助申请窗口（付款后 N 天内）。超期不是拒开，是转客服人工登记，后台开具不受此限：
    # 法定义务不能因为过了自助窗口就消失；而窗口也不能无限宽——跳年开票需财务专项处理。
    INVOICE_APPLY_DAYS: int = 90
    INVOICE_ISSUE_PROMISE_DAYS: int = 3        # 承诺开具时限（工作日），申请回执与前端提示都按这个数展示
    # 开票项目名（含税收分类编码前缀）。由财务确认后只改这一处，不要在代码里再写第二份：
    # 两处不一致的结果是台账记的项目名与税局实际开出的不符，而那正是税务检查时要对的。
    INVOICE_ITEM_NAME: str = "*信息技术服务*信息系统服务费"
    # 前端静态资源目录（同源托管，前端纯展示、不存数据）；留空则不托管（生产由 nginx 提供）
    WEB_ROOT: str = ""
    # 【未接线·无代码读取本键】原意是「默认不替使用者播种垂直业务商品」，但实际种子
    # 只有 main._seed_base_data 一处（播会员档位），插件自己的 seed_data 钩子无条件执行，
    # 因此这个开关从未生效。要控制插件商品的播种请在插件的 seed_data 内自行判定，
    # 别改本键——改 true/false 都不改变任何行为。
    SEED_VERTICAL_PRODUCTS: bool = False
    # M3①（第五十六条第3款）：支付前免责勾选的服务端闸门开关。
    # 此前 DOC_PAYMENT_DISCLAIMER 只由前端写留痕、下单路径不校验（不勾也能付款）。
    # 置 True 后 order.create 在年龄门槛之后调用 distribution_compliance.has_signed
    # 校验用户是否已签署支付免责，未签即拒单。
    # 默认 False 保持兼容：通用底座的占位前端没有签署 UI，无条件强制会导致上线即全员
    # 无法下单；运营接好勾选前端（经 POST /consent/sign 端点、doc_type=payment_disclaimer
    # 写留痕，见 services/consent.py 的 sign）后再置 True，让「不勾也能付款」的合规缺口闭合。
    ENFORCE_PAYMENT_DISCLAIMER: bool = False
    # 会员（对齐《会员体系规则 V1.3》：固定天数制，月30天/年365天/终身永久）
    MEMBERSHIP_MONTH_DAYS: int = 30
    MEMBERSHIP_YEAR_DAYS: int = 365
    MEMBERSHIP_GRACE_HOURS: int = 72          # 到期后宽限期：权益按免费处理，仅保留连续身份标记
    MEMBERSHIP_RULE_VERSION: str = "V1.3"     # 购买时写入 user_memberships.rule_version
    # 档位名，前端会员中心与购买页展示用
    # 档位名属业务侧文案，底座只给中性默认值；垂直业务可覆盖。
    MEMBERSHIP_TIER_NAME: dict = {"month": "月卡会员", "year": "年卡会员", "lifetime": "终身会员"}
    # 档位 SKU 单一来源：既是 _seed_base_data 播种的商品码，也是 membership.level_of_sku
    # 的反查兜底。此前种子钩子把 vip_month/vip_year/vip_lifetime 写死在 main.py 里，而
    # level_of_sku 只认插件 manifest.membership_skus——接入的业务插件不声明会员档时，
    # 用户买下底座档位会在履约处抛 ValueError(非会员SKU)：钱已收、会员没到、订单卡住。
    # 垂直业务若用别的码，在插件 manifest 声明 membership_skus（优先于本表）并覆盖本表。
    MEMBERSHIP_TIER_SKUS: dict = {"month": "vip_month", "year": "vip_year",
                                  "lifetime": "vip_lifetime"}
    # 额度模型：周期总额度为各能力共享的一个总池；单能力单日上限独立计；
    # period_days 为额度周期长度（终身每365天滚动重置）。
    # archive_limit 是历史键名（各档位可保存的条目数上限，0=不限），会员规则文案与
    # 前端已按此键取值，保留键名以避免接口破坏。
    MEMBERSHIP_QUOTA: dict = {
        "month":    {"period_days": 30,  "period_total": 100,  "daily_per_tool": 10,  "archive_limit": 10},
        "year":     {"period_days": 365, "period_total": 1200, "daily_per_tool": 50,  "archive_limit": 50},
        "lifetime": {"period_days": 365, "period_total": 3000, "daily_per_tool": 100, "archive_limit": 0},
    }
    # ===== 分销（对齐《分销规则 V1.4》：一级直推 + 三级等级 + 月度阶梯 + 排行榜 + 业绩为主晋升 + 90天归因）=====
    # 规则文档按部署主体各自公示，底座不绑定任何产品名。
    DISTRIBUTION_ENABLED: bool = True
    # A7：V1.3→V1.4 只改一件事——晋升依据由「人数唯一维度」改为「业绩为主、人数为辅」。
    # 版本号必须跟着口径一起升：文案变了而版本号没变，就无法向监管证明「哪一版规则在何时公示过」，
    # 也无法用 rule_change 留痕区分用户确认的是旧口径还是新口径。
    DISTRIBUTION_RULE_VERSION: str = "V1.4"
    COMMISSION_SETTLE_DAYS: int = 7          # 第二十八条 T+7：支付成功满 7×24 小时（支付当日不计）转已结算
    WITHDRAW_MIN: float = 10.00              # 第三十条：最低提现 10 元
    H5_BASE_URL: str = ""

    # --- 三级等级基础佣金比例（第十三条）：0普通(青铜)/1高级(白银)/2合伙人(黄金) ---
    DIST_LEVEL_BASE_RATE: dict = {0: 0.30, 1: 0.40, 2: 0.50}
    DIST_LEVEL_NAME: dict = {0: "普通推广员", 1: "高级推广员", 2: "合伙人"}
    DIST_LEVEL_BADGE: dict = {0: "青铜", 1: "白银", 2: "黄金"}
    DIST_COMMISSION_CAP: float = 0.60        # 第十五条：单笔佣金比例上限（合伙人 50% + 月度阶梯最高 10%）
    # --- 晋升门槛（第十六、十七条）：A7 整改——业绩为主、人数为辅，两者同时达标才晋升 ---
    # 原口径「唯一维度=验证付费用户数，不考核推广金额」正落在《禁止传销条例》第七条第(二)项
    # 「以发展人员的数量为依据计算和给付报酬」的表述上：等级决定费率，等级只看人数，等于费率
    # 由拉人数量决定——即便单笔佣金按订单实付计算，晋升结构本身已构成「人头」导向。
    # 整改后：累计推广业绩（销售业绩）为主要门槛，验证付费用户数降为辅助条件，人数从此
    # 不再是唯一维度；辅助条件保留是为了防止「一笔大额自买自卖冲业绩」绕过真实推广。
    # 业绩口径 = sum(monthly_performances.total_amount)，与月度阶梯/排行榜完全一致（名下订单
    # 支付成功实付之和扣退款）。复用已有的账而不是新增计数列：另起一列必然与月度业绩口径
    # 分叉（退款冲减只改了其中一处），而「晋升看的业绩」与「阶梯看的业绩」不一致本身就是纠纷源。
    DIST_PROMOTE_PERFORMANCE: dict = {1: 1000.0, 2: 10000.0}   # 累计推广业绩门槛（元）：升 level1/level2
    DIST_PROMOTE_THRESHOLD: dict = {1: 10, 2: 50}   # 辅助条件：验证付费用户数（累计）
    DIST_VERIFY_REFUND_DAYS: int = 7         # 首次付费过 7 天退款期未退款才计为验证付费用户
    # --- 月度阶梯上浮（第二十、二十一条）：按当月「月度推广总金额」（支付成功口径扣退款）；临界点达到即升 ---
    # 结构 [门槛, 上浮比例]，从高到低匹配；恰好 3000 按 +5%、恰好 10000 按 +10%
    DIST_LADDER: list = [[10000.0, 0.10], [3000.0, 0.05], [0.0, 0.0]]
    # --- 月度排行榜（第二十三~二十七条）：名次 + 门槛双达标，未达门槛不发/不降档/不替补；并列平分、总池封顶 ---
    # 结构 [名次起, 名次止, 单人奖金, 最低月度推广门槛]；总池上限=无并列时 1-20 名奖金之和（服务侧据此计算，=4200）
    DIST_RANK_REWARD: list = [
        [1, 1, 1000.0, 10000.0],
        [2, 2, 500.0, 6000.0],
        [3, 3, 300.0, 3000.0],
        [4, 10, 200.0, 1000.0],
        [11, 20, 100.0, 500.0],
    ]
    DIST_MONTHLY_SETTLE_DAY: int = 8         # 第二十九条：每月 8 号 0-6 点结算上月阶梯差额与排行榜奖励（含追回）
    # --- 归因（第三十六、三十七条）：90 天窗口 + 注册前末次有效触达 + 注册后首次绑定永久有效 ---
    DIST_ATTRIBUTION_WINDOW_DAYS: int = 90
    # --- 提现风控（第三十条）：每自然日最多 2 次，00:00 重置；非推广员原因失败返还当次次数 ---
    WITHDRAW_DAILY_LIMIT: int = 2
    # --- 合规入门考试（第七条）：满分 100、80 及格、不限次数 ---
    # 运营决策（本次）：合规考试先停用——DIST_EXAM_ENABLED=False 时不作为计佣/解冻门禁、前端不再提示，
    # 题库/记录/端点保留闲置；将来置 True 即恢复第七条“未通过不予推广资格”硬门禁。
    DIST_EXAM_ENABLED: bool = False
    DIST_EXAM_PASS_SCORE: int = 80
    DIST_EXAM_FULL_SCORE: int = 100
    # --- 违规冻结（第六十条中度违规）：冻结 7 天，冻结期佣金不结算、链接暂停新增绑定、新订单不计业绩 ---
    DIST_FREEZE_DAYS: int = 7
    # 【未接线·全库无任何读取方】第五十九条：承诺书/考试/勾选/处置记录留痕不少于 3 年。
    # 该年限目前只写在这里：没有任何清理任务或查询引用它（distribution_compliance.py 只在
    # 模块 docstring 里提了一句）。法定保存义务并未因此落空：compliance_consents 从不删行，
    # 撤回一律是追加 agreed=0，留痕事实上永久保留。保留本字段是为了把法定期限固化在
    # 配置里；将来若真要加「超期归档/清理」任务，必须以本值为下限，且不得删除留痕行本身。
    DIST_CONSENT_RETENTION_YEARS: int = 3
    # 管理后台
    ADMIN_TOKEN: str = "change-me-admin-token"
    # 管理后台敏感操作二次密码（N20，留空则不强制，生产强烈建议配置）
    ADMIN_OPERATE_PASSWORD: str = ""
    # 管理后台允许的来源 IP 白名单（逗号分隔，留空不限制；生产建议配置办公 IP）
    ADMIN_IP_WHITELIST: str = ""
    # ===== v7 限流配置（M12 计费接口限流 / H1 管理接口防爆破 / N13 防重复下单）=====
    RATE_LIMIT_ADMIN_FAIL_LOCK: int = 5        # 管理令牌连续失败 N 次锁定
    RATE_LIMIT_ADMIN_LOCK_SECONDS: int = 1800  # 锁定时长（秒）
    RATE_LIMIT_ORDER_PER_MIN: int = 10         # 每用户每分钟下单次数
    RATE_LIMIT_UPLOAD_PER_MIN: int = 10        # 每用户每分钟图片上传次数（防内存/CPU 耗尽）
    RATE_LIMIT_FEEDBACK_PER_MIN: int = 5       # 每用户每分钟反馈提交次数
    # 合规留痕（/user/consent 与 /user/consent/withdraw）每次调用都向 compliance_consents
    # 追加一行，而这些行是法定证据、保存≥3 年且任何路径都不会删除（删行等于销毁证据）。
    # 注册零门槛（设备码即得 token），无限流时可被脚本灌满该表：既造成不可回收的存储增长，
    # 更要紧的是把「平台履行了告知同意义务」这张证据表本身淹掉——事后无从辨认哪条是真的。
    # 正常用户一次支付/建档最多触发两三次勾选，10 次/分钟已远超真实用量。
    RATE_LIMIT_CONSENT_PER_MIN: int = 10       # 每用户每分钟合规留痕写入次数
    RATE_LIMIT_TOUCH_PER_HOUR: int = 60        # 每 IP 每小时推广触达上报次数（公开端点，防刷表）
    # ===== V-5 第三方计费接口全局限流 =====
    # 用户级限流可被「注册大量账号」的多账号放大器绕过（每账号都拿到自己的配额），
    # 叠加一层按 IP 的全局限流，防止一次性打爆第三方付费 API 预算。
    # 仅叠加在用户级限流之上；配合 TRUST_PROXY_HEADERS=true（nginx 反代覆写 X-Real-IP）时
    # 按真实公网 IP 计数，直连部署则按 TCP 对端 IP 计数。
    # 【未接线·无代码读取本键】上面那段「按 IP 叠一层全局限流」的设计尚未落地：
    # 现有限流都是按端点各自取 RATE_LIMIT_* 键，没有任何调用点读这个总闸。
    # 待接线说明：在计费类路由上以 f"tp:{ip}" 为键统一计数后再启用，否则别依赖它。
    RATE_LIMIT_TP_GLOBAL_PER_MIN: int = 60     # 每 IP 每分钟第三方计费接口调用总上限
    # 会员配额不在此配置：已由 services/quota.py 的 v2 模型统一承接
    # （各能力共享周期总池 + 单能力单日上限，额度取自 membership.quota_conf(level)）。
    # 新增能力配额请改 quota_conf，不要再按功能分设同类字段。
    # 提现个税（N10）：劳务报酬代扣，0 表示不代扣（需自行承担申报义务）
    WITHDRAW_TAX_ENABLED: bool = False
    WITHDRAW_TAX_RATE: float = 0.20

    @property
    def database_url(self):
        """返回 SQLAlchemy URL 对象（而非拼接串）。

        【安全审计修复 P2-4】原实现用 f-string 把 DB_PASSWORD 拼进连接串，
        create_engine 收到的字符串在连接失败时会原样进入异常文本/日志/APM/监控，
        等于把库密码写进每一条排障信息。改用 URL.create 后，engine.url 的默认
        repr/str 会把密码渲染为 ***（SQLAlchemy 内建掩码），连接行为完全等价
        （create_async_engine 内部本就是把字符串解析成同款 URL 对象）。
        charset 经 query 传入，与旧串尾 ?charset=utf8mb4 等效。"""
        from sqlalchemy.engine import URL
        if self.DB_TYPE == "sqlite":
            return URL.create("sqlite+aiosqlite", database=self.SQLITE_PATH)
        return URL.create(
            "mysql+aiomysql",
            username=self.DB_USER,
            password=self.DB_PASSWORD,
            host=self.DB_HOST,
            port=self.DB_PORT,
            database=self.DB_NAME,
            query={"charset": "utf8mb4"},
        )

    @property
    def redis_url(self) -> str:
        auth = f":{self.REDIS_PASSWORD}@" if self.REDIS_PASSWORD else ""
        return f"redis://{auth}{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"

    @property
    def cors_origins_list(self) -> list:
        return [o.strip() for o in (self.CORS_ORIGINS or "").split(",") if o.strip()]

    @property
    def is_prod_env(self) -> bool:
        """是否按生产环境处理（安全红线的唯一判定入口）。

        启动自检、CORS 是否允许 *、模拟支付是否放行三处必须共用本属性；
        此前各处各写一份 APP_ENV == "production"，任何一处漏改就等于留了裸奔口子。
        审计 L7：默认按生产处理 = 拼写错误（"Product"/"Prod"/"produciton"）与未配置
        等价于 production，行为正确。但运维侧可能在 staging/test 上线时拼错而误以为
        进了非生产模式，特在此打 WARNING 提示「APP_ENV 未命中已知非生产值，将按生产处理」。
        """
        env = (self.APP_ENV or "").strip().lower()
        # 全进程只打一次：is_prod_env 在中间件/请求热路径上被高频调用
        # （CORS/CSP/请求鉴权每条请求都要走一次）。首次提醒「值已加载、运维侧
        # 确认无误」之后静默，避免日志被刷屏。配置变更后重启进程即重新触发，
        # 不影响「首次提示」的运维意图。
        if not getattr(self, "_env_warn_emitted", False):
            import logging
            _log = logging.getLogger(__name__)
            if not env:
                _log.warning("APP_ENV 未配置，按生产环境处理（安全红线全开）")
            elif env not in NON_PROD_ENVS:
                _log.warning(
                    "APP_ENV=%r 未命中已知非生产白名单 %s，按生产环境处理；"
                    "若本意是非生产部署，请检查拼写", env, NON_PROD_ENVS)
            object.__setattr__(self, "_env_warn_emitted", True)
        return env not in NON_PROD_ENVS

    @property
    def admin_ip_whitelist(self) -> list:
        return [o.strip() for o in (self.ADMIN_IP_WHITELIST or "").split(",") if o.strip()]

    class Config:
        env_file = _ENV_FILE
        case_sensitive = True
        # .env 与 docker-compose 共用（MYSQL_ROOT_PASSWORD/MYSQL_DATABASE/TZ 等是
        # 容器基础设施字段，非应用配置）：本地直连运行读 .env 文件时忽略这些多余字段，
        # 与容器内"环境变量注入、多余字段自动忽略"的行为保持一致。
        extra = "ignore"


settings = Settings()
