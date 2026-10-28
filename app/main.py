import logging
import os
import secrets
import time
from contextlib import asynccontextmanager
from urllib.parse import urlsplit
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.staticfiles import StaticFiles
from app.config import settings
from app.core.api import auth, order, payment, user, upload, feedback
from app.core.api import system
from app.core.api import product, membership, distribution, admin, entitlement
from app.plugins import registry
from app.core.api import invoice
from app.core.api import favorite as favorite_api
# 卡券模块（渠道批发卡密）：复用 JWT 鉴权与现有权益/会员表，
# 详见 app/services/card.py 顶部「接入说明」
from app.core.api import card as card_api
from app.core.api import admin_card as admin_card_api
from app.core.api import admin_extra as admin_extra_api
from app.core.api.common import AdminAuthDenied, ErrorCode
from app.core.tasks.scheduler import start_scheduler
from app.core.utils.alert import install_alert_handler, send_alert, alert_ready
from app.core.utils.sanitizer import sanitize_log

# ---- 链路追踪 ----
# 全仓此前没有 request_id/trace_id，一次请求打出的多条日志无法互相关联，
# 排障只能靠业务号（order_no）在海量日志里 grep。这里用 ContextVar 承载，
# 便于在 async 并发下正确隔离（不用全局变量，避免请求间互相污染）。
import contextvars
import uuid

_request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="-")


class _RequestIdFilter(logging.Filter):
    """为每条日志注入当前请求的 request_id。"""

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = _request_id_var.get()
        return True

# T1：进程级统一东八区，保证 datetime.now() 与业务一致
try:
    os.environ.setdefault("TZ", settings.APP_TIMEZONE)
    if hasattr(time, "tzset"):
        time.tzset()
except Exception as _tz_err:
    # Windows 没有 tzset（已被 hasattr 挡住），真正会走到这里的是 TZ 写入被拒。
    # 只能沿用系统时区，但必须留痕：东八区没生效会让全部 datetime.now()
    # 口径整体偏移（配额的自然日/自然月边界、报告卡死阈值都跟着错）。
    # 此处 logger 尚未定义（在下方 basicConfig 之后），直接用 logging 模块。
    logging.getLogger(__name__).warning(
        "进程时区初始化失败，将沿用系统时区: %s", _tz_err)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
# 先挂 filter、再换 formatter：顺序反了会因 %(request_id)s 取不到而导致
# 日志格式化本身抛错（那是比「没有链路 ID」严重得多的故障）。
for _handler in logging.getLogger().handlers:
    _handler.addFilter(_RequestIdFilter())
    _handler.setFormatter(logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - [rid=%(request_id)s] - %(message)s"))
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("应用启动中...")
    # B2：告警通道必须在启动自检之前接入。自检的阻断项与强烈建议项都是 ERROR 级，
    # 而「服务因配置错误起不来」正是最需要有人立刻知道的故障；晚挂一步就一条也发不出去。
    install_alert_handler()
    try:
        _startup_check()
    except RuntimeError as e:
        # 自检不过时进程随即退出，Handler 用 create_task 投递的告警来不及发出就随进程一起消失，
        # 所以这里必须 await 一次（force 绕开去重：启动失败不能被同类故障的窗口吞掉）。
        await send_alert("启动自检未通过，服务拒绝启动", str(e), level="CRITICAL", force=True)
        raise
    if settings.DB_TYPE == "sqlite":
        await _init_sqlite_schema()
    await _seed_base_data()
    start_scheduler()
    yield
    logger.info("应用关闭中...")


# 环境红线判定统一收敛到 settings.is_prod_env（config.py）：启动自检、CORS 放行
# 必须同一口径，本文件不再各自维护一份白名单。
def _is_prod_env() -> bool:
    return settings.is_prod_env


# .env.example 里的开发用密钥。长度都过了下面的强度门槛，故必须单独按值比对。
_SAMPLE_SECRET_VALUES = {
    "JWT_SECRET_KEY": "dev-only-jwt-secret-please-replace-0123456789abcdef",
    "ADMIN_TOKEN": "dev-admin-token-replace-me",
    "SENSITIVE_FIELD_KEY": "dev-only-sensitive-field-key-0123456789",
}


def _startup_check():
    """启动自检：默认密钥/弱密码/生产CORS/HTTPS回调（H5/N14/N9）
    H1：密钥类检查改为 fail-closed——任何环境（含开发/演示）未配置或仍用默认值一律阻断启动，
    不再按环境白名单放行已知密钥。"""
    warns = []
    errors = []
    blocking = []
    # 安全强烈建议：ERROR 级日志醒目提示，但不参与下方 raise 判定（不阻断启动）。
    # 用于「最高安全提示、但硬阻断会让合法部署起不来」的项（如生产未配管理端 IP 白名单）。
    advisories = []
    # H1：JWT/管理令牌必须显式配置，默认空值或弱值在任意环境直接阻断（fail-closed）
    # P3 修复：JWT 密钥最低长度 16→32（HS256 抗暴力破解的有效熵下限），并限定算法白名单
    if not settings.JWT_SECRET_KEY or settings.JWT_SECRET_KEY.strip().startswith("change-me") \
            or len(settings.JWT_SECRET_KEY.strip()) < 32:
        blocking.append("JWT_SECRET_KEY 未配置或强度不足（至少 32 位随机串），必须设置")
    if settings.JWT_ALGORITHM not in ("HS256", "HS384", "HS512"):
        blocking.append(f"JWT_ALGORITHM 仅允许 HS256/HS384/HS512，当前为 {settings.JWT_ALGORITHM}")
    if not settings.ADMIN_TOKEN or settings.ADMIN_TOKEN.strip().startswith("change-me") \
            or len(settings.ADMIN_TOKEN.strip()) < 8:
        blocking.append("ADMIN_TOKEN 未配置或强度不足（至少 8 位随机串），必须设置")
    # A6：敏感字段加密密钥。不配也能跑（crypto_field 会降级为明文落库并刷 critical），
    # 但那意味着全库收款账号与真实姓名以明文存储：一旦拖库或备份外泄就是直接的资金损失，
    # 且属《个保法》第五十一条明确要求的技术措施。与 JWT 同级处理：阻断启动，不给「先上线再补」的机会。
    if not settings.SENSITIVE_FIELD_KEY or settings.SENSITIVE_FIELD_KEY.strip().startswith("change-me") \
            or len(settings.SENSITIVE_FIELD_KEY.strip()) < 16:
        blocking.append("SENSITIVE_FIELD_KEY 未配置或强度不足（至少 16 位随机串，建议 openssl rand -hex 32），"
                        "收款账号与实名将以明文落库，必须设置")
    # 安全红线：SQLite 仅限非生产环境，防止演示配置裸奔上线
    if settings.DB_TYPE == "sqlite":
        warns.append("当前使用 SQLite，生产环境请使用 MySQL")
    # N14：数据库/Redis 弱密码检查。占位默认口令只 warn 拦不住误部署：
    # 生产环境（is_prod_env）升级为阻断（fail-closed，与 JWT/ADMIN_TOKEN 同一哲学）——
    # MySQL 用默认/弱口令等于把资金库钥匙挂在门上；非生产保持告警，方便本地/测试起库。
    # SQLite 本地文件不联网，DB_PASSWORD 无意义，不做数据库侧判定。
    _weak_pwd_msgs = []
    if settings.DB_TYPE == "mysql":
        # 通用底座不再把某个产品的历史默认口令写进名单（那是产品残留），
        # 只保留通用占位值与常见弱口令。
        for weak in ("please-change", "123456", "password", "changeme", "app123456"):
            if weak in (settings.DB_PASSWORD or ""):
                _weak_pwd_msgs.append(f"数据库密码为默认/弱密码（命中 {weak}），生产严禁使用")
    if settings.REDIS_PASSWORD:
        for weak in ("please-change", "123456", "password", "changeme", "app123456"):
            if weak in settings.REDIS_PASSWORD:
                _weak_pwd_msgs.append("Redis 密码为弱密码，生产严禁使用")
    for _m in _weak_pwd_msgs:
        (errors if _is_prod_env() else warns).append(_m)
    if not settings.WECHAT_MCH_ID:
        warns.append("微信支付未配置")
    else:
        # 回调验签凭据二选一：平台证书 或 微信支付公钥（官方推荐，无需 5 年轮换）。
        # 两者皆缺时回调会被全部拒绝，提前告警。
        if not settings.WECHAT_PLATFORM_CERT_PATH and not settings.WECHAT_PUBLIC_KEY_PATH:
            warns.append("微信支付已配置但缺少 WECHAT_PLATFORM_CERT_PATH 平台证书与 "
                         "WECHAT_PUBLIC_KEY_PATH 微信支付公钥，支付回调将被全部拒绝")
        if not settings.WECHAT_API_V3_KEY:
            warns.append("微信支付缺少 WECHAT_API_V3_KEY，回调无法解密、退款不可用")
        if not settings.WECHAT_CERT_SERIAL_NO:
            warns.append("微信支付缺少 WECHAT_CERT_SERIAL_NO，接口请求签名将失败")
    if not settings.ALIPAY_APP_ID:
        warns.append("支付宝未配置")
    if not (settings.COS_SECRET_ID and settings.COS_BUCKET):
        warns.append("腾讯云COS未配置，头像/反馈图片上传不可用")
    # H5：生产环境必须显式配置 CORS，绝不允许 *
    if _is_prod_env():
        # 模拟支付仅用于本地演示链路，生产开启等于白送商品
        if settings.PAYMENT_MOCK:
            errors.append("PAYMENT_MOCK 仅限本地演示，生产环境必须关闭")
        # 示例密钥逐字节比对：.env.example 里的三个 dev 值长度都过得了上面的强度门槛，
        # 照抄的部署能正常启动，等于用全仓库公开的密钥签发会话/解密密文。
        # 只在生产阻断（本地开发本来就用它们），保证 README 的 cp .env.example .env 流程可用。
        for _name, _sample in _SAMPLE_SECRET_VALUES.items():
            if getattr(settings, _name, "") == _sample:
                errors.append(f"{_name} 仍是 .env.example 的示例值，生产环境必须替换")
        if not settings.cors_origins_list:
            errors.append("生产环境必须配置 CORS_ORIGINS（H5 前端域名），禁止放行所有来源")
        # N9：支付回调必须 HTTPS
        for url_name in ("WECHAT_NOTIFY_URL", "ALIPAY_NOTIFY_URL"):
            url = getattr(settings, url_name, "")
            if url and url.startswith("http://"):
                warns.append(f"{url_name} 使用了 HTTP，微信/支付宝支付回调要求 HTTPS")
        # M6：生产环境管理端资金操作必须配置二次密码（退款/提现打款/会员调整的最后一道门）
        if not settings.ADMIN_OPERATE_PASSWORD:
            errors.append("生产环境必须配置 ADMIN_OPERATE_PASSWORD（管理端敏感操作二次密码）")
        # 安全加固：默认管理令牌硬编码在代码里（=公开已知），生产未配置或仍用默认值时 fail-closed，
        # 防止 .env 缺行时管理端带着仓库里人人可得的默认令牌上线。
        if not settings.ADMIN_TOKEN or settings.ADMIN_TOKEN == "change-me-admin-token":
            errors.append("生产环境必须在 .env 配置自定义 ADMIN_TOKEN，禁止使用代码默认值")
        # A4 合规：AI 生成合成内容必须带真实服务提供者标识（《标识办法》+ GB 45438-2025）。
        # 底座不预设任何产品名，留空即无法生成合规的隐式标识，故生产阻断。
        if not (settings.AI_MARK_PROVIDER_NAME or "").strip():
            errors.append("生产环境必须配置 AI_MARK_PROVIDER_NAME（AI 生成内容标识的服务提供者名称，"
                          "须为真实备案/经营主体，不得留空）")
        # 门禁纵深防御：生产未配 IP 白名单 → ERROR 级醒目告警但不阻断。
        # 不做硬阻断的原因：管理端可能在公网靠强令牌+VPN/堡垒机运维，无固定办公 IP 的合法部署
        # 一旦被强制白名单就会上线即起不来；用最强告警替代阻断，兼顾「最高安全提示」与「可上线」。
        if not settings.admin_ip_whitelist:
            _msg = ("生产环境未配置 ADMIN_IP_WHITELIST，管理端对全网暴露（仅靠强令牌+爆破锁定），"
                    "强烈建议限定办公/堡垒机出口 IP")
            if settings.SECURITY_STRICT_IP_POLICY:
                errors.append(_msg + "（SECURITY_STRICT_IP_POLICY=true，已升级为阻断项）")
            else:
                advisories.append(_msg + "；若确无固定出口 IP，可置 SECURITY_STRICT_IP_POLICY=false 保持现状")
        elif not settings.TRUST_PROXY_HEADERS:
            # 白名单×反代头联动陷阱：配了白名单却未信任代理头时，nginx 后 get_client_ip 拿到内网 IP，
            # 会把所有真实管理员误拒（或若把内网段加进白名单则形同虚设）——提前告警避免上线即锁死后台
            warns.append("已配 ADMIN_IP_WHITELIST 但 TRUST_PROXY_HEADERS=false：若部署在反代之后，客户端 IP "
                         "会是内网地址导致白名单误拒，请确认反代覆写 X-Real-IP 并置 TRUST_PROXY_HEADERS=true")
        # 密钥强度提示（fail-closed 下限已在上方 blocking 校验，此处仅建议更强，不阻断）
        if len((settings.ADMIN_TOKEN or "").strip()) < 16:
            warns.append("ADMIN_TOKEN 长度不足 16 位，生产建议使用更长随机串")
        if settings.ADMIN_OPERATE_PASSWORD and len(settings.ADMIN_OPERATE_PASSWORD.strip()) < 8:
            warns.append("ADMIN_OPERATE_PASSWORD 长度不足 8 位，生产建议使用更强操作密码")
        # P5：信任反代头但未配共享密钥 → 同机任何进程（运维脚本、容器内副服务、被渗透的旁路
        # 容器）都可直连 127.0.0.1:8002 并伪造 X-Real-IP，从而绕过 IP 维度限流、管理端爆破锁定、
        # 以及将来任何基于 IP 的安全策略。不阻断（同上：合理部署可能确实不配密钥），用最高告警。
        if settings.TRUST_PROXY_HEADERS and not (settings.PROXY_AUTH_SECRET or "").strip():
            _msg = ("TRUST_PROXY_HEADERS=true 但 PROXY_AUTH_SECRET 未配置：同机进程可直连 "
                    "127.0.0.1:8002 并伪造 X-Real-IP，绕过 IP 维度限流与管理端爆破锁定；"
                    "请配置密钥并让反向代理注入 X-Proxy-Auth 头（至少 32 位随机串）")
            if settings.SECURITY_STRICT_IP_POLICY:
                errors.append(_msg + "（SECURITY_STRICT_IP_POLICY=true，已升级为阻断项）")
            else:
                advisories.append(_msg + "；确认无法注入该头时可置 SECURITY_STRICT_IP_POLICY=false 保持现状")
        # B2：告警通道。不做硬阻断的理由与 IP 白名单一致：没配机器人也能合法上线（自己看日志），
        # 但资金类故障（退款重试耗尽、金额与渠道不符、对账差错）的发现时延直接等于资损金额，
        # 所以用最高级别的醒目告警提示，而不是静默跳过。
        if not alert_ready():
            advisories.append("生产环境未接入告警通道（ALERT_WECOM_WEBHOOK / ALERT_DINGTALK_WEBHOOK 未配），"
                              "退款重试耗尽、掉单金额不符、对账差错等 ERROR 仅落容器 stdout，"
                              "需人工轮询日志才能发现（建议配企业微信或钉钉群机器人）")
    elif settings.PAYMENT_MOCK:
        # 非生产里的模拟支付是刻意开启的演示能力，但一旦这台机器被当测试环境给外部访问，
        # 任何人注册后都能免费拿到全部商品。每次启动都留一条醒目记录，便于事后追溯。
        warns.append("PAYMENT_MOCK=true：模拟支付已开启，任何人注册后可不付款完成下单（仅限本地演示）")
    for w in warns:
        logger.warning(f"[启动自检] {w}")
    for a in advisories:
        logger.error(f"[启动自检-安全强烈建议] {a}")
    for e in errors:
        logger.error(f"[启动自检-阻断项] {e}")
    if blocking:
        # 密钥类阻断项：任意环境一律拒绝启动（fail-closed），防止默认密钥裸奔
        raise RuntimeError("启动自检未通过：" + "；".join(blocking))
    if errors and _is_prod_env():
        # 生产环境存在阻断项直接拒绝启动，避免裸奔上线；
        # 非生产环境（开发/演示）允许带告警启动
        raise RuntimeError("启动自检未通过：" + "；".join(errors))


async def _init_sqlite_schema():
    """SQLite 轻量部署：按 ORM 模型建表（MySQL 部署仍用 sql/init.sql）"""
    from app.core.database import engine, Base
    from app.core import models  # noqa: F401 确保全部模型注册到 metadata
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("SQLite 表结构已就绪")


async def _seed_base_data():
    """商品与系统配置种子（仅表为空时写入）。

    通用底座只播种会员档位这类与底座能力直接对应的商品；
    垂直业务商品由 SEED_VERTICAL_PRODUCTS 开关控制，默认不播种。
    定价与 sql/init.sql 保持一致。
    """
    from sqlalchemy import select
    from app.core.database import AsyncSessionLocal
    from app.core.models import Product, SystemConfig
    async with AsyncSessionLocal() as db:
        has_product = (await db.execute(select(Product.id).limit(1))).scalar_one_or_none()
        if not has_product:
            # 通用底座只播种会员档位；具体业务能力商品由 app/plugins/<业务>/ 的
            # manifest 声明，经注册表在下单链路按能力码动态取价，不在此预置。
            seeds = [
                Product(sku_code="vip_month", product_type="membership", feature="vip",
                        name="月卡会员", description="开通起30天：会员权益、周期总额度100次、单能力单日10次",
                        price="99.00", refund_rule="虚拟内容服务，支付后7天内未使用可联系客服退款",
                        sort_order=1, enabled=1),
                Product(sku_code="vip_year", product_type="membership", feature="vip",
                        name="年卡会员", description="开通起365天：会员权益、周期总额度1200次、单能力单日50次、优先客服",
                        price="299.00", refund_rule="虚拟内容服务，支付后7天内未使用可联系客服退款",
                        sort_order=2, enabled=1),
                Product(sku_code="vip_lifetime", product_type="membership", feature="vip",
                        name="终身会员", description="平台运营期内永久：会员权益、每365天周期总额度3000次、单能力单日100次、最高优先客服",
                        price="599.00", refund_rule="虚拟内容服务，支付后7天内未使用可联系客服退款",
                        sort_order=3, enabled=1),
            ]
            db.add_all(seeds)
            logger.info("已写入通用商品种子数据（会员档位）")

        # 会员商品幂等同步到 V1.3（老库不跑历史迁移脚本也能收敛）：
        # 补插 vip_year；将 vip_month/vip_lifetime 的名称/描述/定价/排序同步到规则口径。
        # 只改商品定义，不动任何已支付订单（第七条第4款：调价不溯及已支付订单）。
        vip_specs = {
            "vip_month": ("月卡会员", "99.00", 1,
                          "开通起30天：会员权益、周期总额度100次、单能力单日10次"),
            "vip_year": ("年卡会员", "299.00", 2,
                         "开通起365天：会员权益、周期总额度1200次、单能力单日50次、优先客服"),
            "vip_lifetime": ("终身会员", "599.00", 3,
                             "平台运营期内永久：会员权益、每365天周期总额度3000次、单能力单日100次、最高优先客服"),
        }
        for sku, (nm, price, sort, desc) in vip_specs.items():
            row = (await db.execute(select(Product).where(Product.sku_code == sku))).scalar_one_or_none()
            if row is None:
                db.add(Product(sku_code=sku, product_type="membership", feature="vip",
                               name=nm, description=desc, price=price,
                               refund_rule="虚拟内容服务，支付后7天内未使用可联系客服退款",
                               sort_order=sort, enabled=1))
                logger.info("已补插会员商品 %s（%s）", sku, price)
            else:
                row.name, row.price, row.sort_order, row.description, row.enabled = nm, price, sort, desc, 1
        # 会员权益简述（会员中心「会员权益」展示）：文案不再写死工具数量，
        # 新增会员工具后无需同步改文案；完整会员规则由 /api/membership/rules 下发。
        vip_benefits_v13 = [
            "会员期内解锁全部业务能力（具体能力清单由已接入的业务插件提供）",
            "周期总额度池全部能力共享，历史报告可查（具体额度见会员规则）",
            "优先客服与新能力优先体验",
        ]
        has_cfg = (await db.execute(select(SystemConfig.id).limit(1))).scalar_one_or_none()
        if not has_cfg:
            cfgs = [
                SystemConfig(config_key="paid_reports_enabled", config_value=True),
                SystemConfig(config_key="refund_enabled", config_value=True),
                SystemConfig(config_key="distribution_enabled", config_value=True),
                SystemConfig(config_key="announcement", config_value=""),
                SystemConfig(config_key="vip_benefits", config_value=vip_benefits_v13),
            ]
            db.add_all(cfgs)
            logger.info("已写入系统配置种子数据")
        else:
            # 全新通用底座不含任何遗留业务文案，无需 vip_benefits 迁移；
            # 既有库的运营自定义值一律保留不覆盖。
            pass
        # ===== 业务插件种子（可选钩子）=====
        # 通用底盘不认识任何具体业务；插件若声明 seed_data(db) 则由启动流程调用，
        # 用于把自己的可售商品写进 products 表（价源仍以 manifest 为准）。
        for _entry in registry.plugins.values():
            _seeder = getattr(_entry.service, "seed_data", None)
            if _seeder is not None:
                await _seeder(db)
                logger.info("插件 %s 已执行 seed_data", _entry.name)
        await db.commit()


app = FastAPI(
    title="通用应用后端 API",
    description="会员、单次/按天权益、微信/支付宝支付、一级直推分销与提现审核",
    version="7.0.0",
    lifespan=lifespan,
    # 安全加固：生产关闭 docs/redoc/openapi，避免匿名公网获取完整 API 地图
    #（含管理端端点与请求/响应结构，等于给攻击者递地图）；非生产保留便于调试。
    docs_url=None if _is_prod_env() else "/docs",
    redoc_url=None if _is_prod_env() else "/redoc",
    openapi_url=None if _is_prod_env() else "/openapi.json",
)

# H5 修复：生产环境未配置来源时不放行 *；仅开发环境放开
_origins = settings.cors_origins_list
# 用统一判定：APP_ENV 拼错时若仍按 != "production" 放行 *，跨域白名单就等于没有
if not _origins and not settings.is_prod_env:
    _origins = ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,                       # 生产为空则不设置任何放行来源
    allow_credentials=bool(_origins and _origins != ["*"]),
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Requested-With",
                   "X-CSRF-Token", "X-Admin-Token", "X-Request-ID"],
)

# gzip：js/regions.js 由「省-市」两级扩到「省-市-区县」三级后体积涨到 145KB
# （34 省 / 344 市 / 2870 区县，每级都带政府驻地经纬度），纯文本压缩率约 4:1。
# 开发态尤其必要：下面的 _static_no_cache 对所有非 /api 路径下发 no-store，
# 浏览器不缓存，每次打开页面都要全量重传这个文件。
# 生产由 nginx 提供静态资源时这段不生效（WEB_ROOT 为空），压缩在 nginx.conf 里配。
# minimum_size=1024：更小的响应压缩头本身就有 20 余字节，压了反而变大。
app.add_middleware(GZipMiddleware, minimum_size=1024)


# 链路追踪中间件：复用上游传入的 X-Request-ID（便于网关/前端串联），否则生成新的。
@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    rid = request.headers.get("X-Request-ID") or uuid.uuid4().hex[:16]
    token = _request_id_var.set(rid)
    try:
        response = await call_next(request)
    finally:
        _request_id_var.reset(token)
    response.headers["X-Request-ID"] = rid
    return response


# P3（#28 全局请求体上限）：无上限时攻击者可用超大 body 耗尽内存/带宽（multipart 上传另有
# RATE_LIMIT_UPLOAD_PER_MIN 但 body 本身仍可巨大）。
# M2 修复：原实现是 @app.middleware("http")（BaseHTTPMiddleware），只做了 Content-Length 预检，
# 注释宣称的「chunked 流式兜底」从未实现——攻击者用 Transfer-Encoding: chunked（不带 Content-Length）
# 即可绕过预检，让下游 request.body() 把任意大的 body 全量读进内存；且 BaseHTTPMiddleware 下
# request.body() 会先缓冲整个 body 再交下游，结构上就无法做流式限制。
# 改为纯 ASGI 中间件：包装 receive 逐块累计已读字节，超限立即中断，内存占用恒定在上限内。
_MAX_BODY_BYTES = 8 * 1024 * 1024  # 8MB：头像/反馈图上传的合理上限，远超任何 JSON 接口需求


class _BodyTooLarge(Exception):
    """流式读取累计字节超过 _MAX_BODY_BYTES 时抛出，由中间件统一转 413。"""


class BodySizeLimitMiddleware:
    """纯 ASGI 请求体上限中间件（M2）。两道防线：
    · Content-Length 预检：声明超限直接 413，一个字节都不读；
    · 流式兜底：chunked（无 Content-Length）传输时包装 receive 累计已读字节，超限即断。
    仅拦 POST/PUT/PATCH（GET/DELETE 无 body）；仅当下游真的读取 body 时才触发流式计数，
    handler 不读 body 的场景 body 不进内存、无害放行。
    """

    def __init__(self, app, max_bytes: int = _MAX_BODY_BYTES):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("method") not in ("POST", "PUT", "PATCH"):
            await self.app(scope, receive, send)
            return
        # 防线一：Content-Length 预检（ASGI 规范保证 headers 已小写化）
        for _name, _value in scope.get("headers") or []:
            if _name == b"content-length":
                try:
                    if int(_value) > self.max_bytes:
                        await self._reject(scope, receive, send)
                        return
                except (TypeError, ValueError):
                    pass
                break
        # 防线二：流式兜底（chunked 无 Content-Length，或 Content-Length 与实际不符）
        counted = 0
        response_started = False

        async def _limited_receive():
            nonlocal counted
            message = await receive()
            if message["type"] == "http.request":
                counted += len(message.get("body", b"") or b"")
                if counted > self.max_bytes:
                    raise _BodyTooLarge()
            return message

        async def _tracked_send(message):
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, _limited_receive, _tracked_send)
        except _BodyTooLarge:
            # 下游读取 body 时累计超限：响应未开始才能改判 413；已开始（极罕见）则仅记录
            if not response_started:
                logger.warning(f"请求体流式读取超上限已中断 limit={self.max_bytes}")
                await self._reject(scope, receive, send)
            else:
                logger.warning("请求体超限但响应已开始，无法改判 413，已中断后续处理")

    async def _reject(self, scope, receive, send):
        resp = JSONResponse(status_code=413, content={"code": 1001, "msg": "请求体过大"})
        await resp(scope, receive, send)


app.add_middleware(BodySizeLimitMiddleware, max_bytes=_MAX_BODY_BYTES)


# ===== CSRF 保护中间件 =====
# 防止跨站请求伪造：状态变更操作必须能证明请求来自本站
# · /api/*：Bearer 令牌 / 支付回调 / 同源 Origin 三者之一
# · 其余路径：双提交 Cookie（csrf_token + X-CSRF-Token）
class CSRFMiddleware:
    """跨站请求伪造防护。按请求形态走两条判据：

    · `/api/*`（前端主要接口）：满足任一条即放行——
        a) 带 Bearer 令牌：令牌由前端显式放入请求头，浏览器不会自动附带，天然不是 CSRF 面；
        b) 支付平台回调：服务端到服务端，无 Origin/Referer，安全性由验签 + 金额校验 + 幂等保证；
        c) Origin（缺失时回退 Referer）的 host:port 等于请求 Host，或命中 CORS_ORIGINS。
      此前 `/api/*` 被整体豁免，等于只靠 Cookie 的 SameSite=Lax 兜底：部署方一旦为跨域把
      AUTH_COOKIE_SAMESITE 设为 none，CSRF 防护就完全消失（而 SECURITY.md 声称的
      「跨域部署要求自定义头」在代码里并不存在）。现在这条判据把缺口补上。
    · 其余路径（模板表单）：保留双提交 Cookie——csrf_token 与 X-CSRF-Token 必须一致。

    非浏览器客户端用 Cookie 会话发状态变更请求时需自带 Origin，或改用 Bearer 令牌。
    """

    SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}
    SERVER_CALLBACK_PATHS = ("/api/payment/wechat/notify", "/api/payment/alipay/notify")
    TOKEN_EXEMPT_PATHS = ("/login", "/register", "/forgot", "/health")

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "").upper()
        path = scope.get("path", "")

        # 安全方法（不改变状态）直接放行
        if method in self.SAFE_METHODS:
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))

        if path.startswith("/api"):
            if (path in self.SERVER_CALLBACK_PATHS
                    or self._has_bearer(headers)
                    or self._origin_ok(headers)):
                await self.app(scope, receive, send)
                return
            await self._reject(scope, receive, send, "跨站请求来源校验失败")
            return

        if path.startswith(self.TOKEN_EXEMPT_PATHS):
            await self.app(scope, receive, send)
            return

        # 双提交 Cookie：Cookie 里的 csrf_token 与 Header 里的 X-CSRF-Token 必须一致
        cookie_header = headers.get(b"cookie", b"").decode("latin-1")
        csrf_cookie = self._extract_csrf_token(cookie_header)
        x_csrf = headers.get(b"x-csrf-token", b"").decode("latin-1")
        if not csrf_cookie or not x_csrf or not secrets.compare_digest(csrf_cookie, x_csrf):
            await self._reject(scope, receive, send, "CSRF Token 校验失败")
            return

        await self.app(scope, receive, send)

    @staticmethod
    async def _reject(scope, receive, send, msg: str) -> None:
        response = JSONResponse(
            status_code=403,
            content={"code": ErrorCode.CSRF_FAILED, "msg": msg, "data": None},
        )
        await response(scope, receive, send)

    @staticmethod
    def _has_bearer(headers: dict) -> bool:
        auth = headers.get(b"authorization", b"").decode("latin-1").strip()
        return auth.lower().startswith("bearer ") and len(auth) > 7

    @staticmethod
    def _origin_ok(headers: dict) -> bool:
        """Origin/Referer 的 host:port 是否等于请求 Host 或落在 CORS 白名单内。"""
        source = headers.get(b"origin") or headers.get(b"referer") or b""
        try:
            parsed = urlsplit(source.decode("latin-1"))
        except ValueError:
            return False
        # "null"（沙箱 iframe）解析后 scheme/netloc 为空，按跨站处理
        if not parsed.scheme or not parsed.netloc:
            return False
        target = parsed.netloc.lower()
        host = headers.get(b"host", b"").decode("latin-1").strip().lower()
        if host and secrets.compare_digest(target, host):
            return True
        return any(target == urlsplit(o).netloc.lower()
                   for o in settings.cors_origins_list if "://" in o)

    def _extract_csrf_token(self, cookie_header: str) -> str:
        """从 Cookie 中提取 csrf_token"""
        for part in cookie_header.split(";"):
            part = part.strip()
            if part.startswith("csrf_token="):
                return part[11:]
        return ""


app.add_middleware(CSRFMiddleware)


# 安全响应头
@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Permissions-Policy"] = "geolocation=(self)"
    if settings.CSP_ENABLED:
        # CSP 原先完全缺失：仅靠输出转义防 XSS，一旦漏转（已修过的 birth_date 就是例子）
        # 注入内容就能直接执行。script-src 'self' 能把这类漏转从“可执行”降为“仅能改样式/文本”。
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            f"style-src {settings.CSP_STYLE_SRC}; "
            f"img-src {settings.CSP_IMG_SRC}; "
            "font-src 'self' data:; "
            f"connect-src {settings.CSP_CONNECT_SRC}; "
            "form-action 'self' https:; "
            "base-uri 'self'; "
            "object-src 'none'; "
            "frame-ancestors 'none'"
        )
    # H1: HSTS 仅生产 HTTPS 部署下生效（开发环境 HTTP 时浏览器会忽略，置了反而锁死本地）。
    # 配置 1 年 + includeSubDomains：首访 HTTPS 后浏览器即拒绝纯 HTTP 资源，防协议降级/中间人。
    if _is_prod_env():
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    # H2: /api/* 响应全部带用户态信息，任何 CDN/代理缓存都会导致跨用户数据泄露。
    # Vary 头告知代理按 Cookie/Authorization 区分缓存键；no-store 是更硬的兜底，直接禁止落盘。
    if request.url.path.startswith("/api"):
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Vary"] = "Cookie, Authorization"
    return resp


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    # 脱敏日志：防止敏感信息泄露。
    # 【安全审计修复】异常消息本身也要脱敏——请求参数若携带 token/密钥
    # （支付回调 body、URL query 等），会随 {exc} 原文进入容器日志，
    # 并可能经 AlertHandler 外发到第三方 webhook。
    sanitized_path = sanitize_log(request.url.path)
    logger.error(f"未捕获异常 path={sanitized_path}: {sanitize_log(str(exc))}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"code": 500, "msg": "服务器内部错误", "data": None},
    )


# 统一 HTTPException 响应体为 {code,msg,data} 信封（保留原 HTTP 状态码）。
# 起因：主鉴权依赖 get_current_user 对令牌缺失/过期/无效抛 HTTPException(401)、账号禁用抛 403，
# 走 FastAPI 默认处理只回 {"detail":...}；而前端 api.js 只认业务码 code=1002(NOT_LOGIN) 才清 token、
# 并在支付轮询 pollPaid 里据 code=1002 自动重登——令牌过期时这套恢复逻辑形同虚设，用户只见「请求失败」。
# 这里把 401/403/429 映射到既有 ErrorCode，让前端既有的会话恢复链路真正生效，且全站响应体口径一致。
_HTTP_STATUS_TO_CODE = {
    401: ErrorCode.NOT_LOGIN,       # 1002
    403: ErrorCode.NO_PERMISSION,   # 1003
    429: ErrorCode.RATE_LIMIT,      # 1004
}


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    code = _HTTP_STATUS_TO_CODE.get(exc.status_code, exc.status_code)
    # 5xx 内部错误脱敏：不把异常原文回传给客户端，避免堆栈/内部信息泄露
    msg = exc.detail if (isinstance(exc.detail, str) and exc.status_code < 500) else "请求处理失败，请稍后重试"
    return JSONResponse(
        status_code=exc.status_code,
        content={"code": code, "msg": msg, "data": None},
    )


# 统一 pydantic 参数校验失败（HTTP 422）响应体为 {code,msg,data}。
# 起因：FastAPI 默认对 RequestValidationError 只回 {"detail":[{type,loc,msg,ctx}]}
# 这种结构，而全站前端只认 code/msg，于是「密码长度不能少于 8 位」「充值不得小于 1 元」
# 这些后端早已写好的精确中文提示被 pydantic 抢先，用户只能看到兜底的「提交失败，请稍后重试」，
# 甚至去猜“是不是服务挂了”。这里把 detail 翻成人能读的一句话，同时保留 422 状态码
# （传输层监控仍可区分“参数错”与“服务错”，不改变现有 HTTP 语义）。
_FIELD_LABELS = {
    "password": "密码", "email": "邮箱", "code": "验证码", "name": "姓名",
    "contact": "联系方式", "content": "留言内容", "amount_cents": "充值金额",
    "channel": "支付渠道", "endpoint": "接口端点", "params": "调用参数",
    "key_id": "密钥", "nickname": "昵称", "purpose": "用途",
}


def _friendly_validation_error(errors) -> str:
    parts = []
    for e in list(errors or [])[:3]:
        loc = e.get("loc") or ()
        field = str(loc[-1]) if len(loc) > 1 else ""
        label = _FIELD_LABELS.get(field, field or "请求参数")
        etype = e.get("type") or ""
        ctx = e.get("ctx") or {}
        if etype == "missing":
            parts.append(f"请填写{label}")
        elif etype == "string_too_short":
            parts.append(f"{label}长度不能少于 {ctx.get('min_length', '')} 位")
        elif etype == "string_too_long":
            parts.append(f"{label}长度不能超过 {ctx.get('max_length', '')} 位")
        elif etype in ("greater_than_equal", "greater_than"):
            if field == "amount_cents":
                parts.append("充值金额不能少于 1 元")
            else:
                key = "ge" if etype == "greater_than_equal" else "gt"
                parts.append(f"{label}不能小于 {ctx.get(key, '')}")
        elif etype in ("less_than_equal", "less_than"):
            if field == "amount_cents":
                parts.append("单笔充值金额不能超过 1 万元")
            else:
                key = "le" if etype == "less_than_equal" else "lt"
                parts.append(f"{label}不能大于 {ctx.get(key, '')}")
        elif etype in ("value_error", "assert_failed", "model_attributes_type", "dict_type"):
            parts.append(str(e.get("msg") or f"{label}格式不正确"))
        elif etype == "string_pattern_mismatch":
            parts.append(f"{label}格式不正确")
        elif etype == "literal_error":
            parts.append(f"{label}取值不正确")
        else:
            parts.append(f"{label}格式不正确")
    text = "；".join(p for p in parts if p)
    return text or "请求参数有误"


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={"code": ErrorCode.PARAM_ERROR,
                 "msg": _friendly_validation_error(exc.errors()),
                 "data": None},
    )


@app.exception_handler(AdminAuthDenied)
async def admin_auth_denied_handler(request: Request, exc: AdminAuthDenied):
    """管理端鉴权失败：HTTP 401 + 既有业务码 6001。

    上线前检查修复：此前该失败以 HTTP 200 返回，nginx 日志/监控/WAF 无法与正常请求区分，
    令牌爆破在传输层不可观测。改为 401 后可被统计与告警，响应体仍保持 code/msg/data 口径。
    """
    return JSONResponse(
        status_code=401,
        content={"code": ErrorCode.ADMIN_LOCKED, "msg": exc.msg, "data": None},
    )


# 注册路由（统一前缀 /api）。T13：移除遗留 /api/report 旧报告接口，收敛攻击面
app.include_router(auth.router, prefix="/api")
app.include_router(system.router, prefix="/api")
app.include_router(order.router, prefix="/api")
app.include_router(payment.router, prefix="/api")
app.include_router(user.router, prefix="/api")
app.include_router(upload.router, prefix="/api")
app.include_router(feedback.router, prefix="/api")
app.include_router(product.router, prefix="/api")
app.include_router(membership.router, prefix="/api")
app.include_router(distribution.router, prefix="/api")
app.include_router(admin.router, prefix="/api")
app.include_router(admin_extra_api.router, prefix="/api")
app.include_router(entitlement.router, prefix="/api")
app.include_router(invoice.router, prefix="/api")
app.include_router(favorite_api.router, prefix="/api")
app.include_router(card_api.router, prefix="/api")
app.include_router(admin_card_api.router, prefix="/api")

# 插件路由自动挂载（core / main 不 import 任何具体插件）：发现插件 -> 遍历其全部 router。
# 新增业务只需在 app/plugins/ 加目录，这里自动生效，main 零改动。
registry.discover()
for _entry in registry.plugins.values():
    for _r in _entry.routers:
        app.include_router(_r, prefix="/api")


# 同源托管前端时 / 由 SPA 回退逻辑返回 index.html；未配置 WEB_ROOT（nginx 提供静态）时才保留 JSON 探针
if not (settings.WEB_ROOT and os.path.isdir(settings.WEB_ROOT)):
    @app.get("/")
    async def root():
        # P3（#28）：与 /api/server-info 同口径不暴露版本号——精确版本对攻击者是 CVE 指南。
        return {"code": 0, "msg": "后端服务运行中"}


@app.get("/api/server-info")
async def server_info():
    # P3：收敛对外暴露面——版本号对攻击者是「CVE 指南」，对用户无感知价值。
    return {"code": 0, "msg": "service running"}


@app.get("/health")
async def health():
    """L3：对外只返回笼统状态，不暴露 DB/Redis 细节"""
    return {"code": 0, "msg": "ok", "data": {"status": "healthy"}}


# ---------- 前端静态托管（同源部署：前端纯展示、不存数据，一律调后端接口） ----------
# 生产由 nginx 提供时 WEB_ROOT 留空即不启用；配置后 / 下直接访问 H5 页面
if settings.WEB_ROOT and os.path.isdir(settings.WEB_ROOT):
    app.mount("/css", StaticFiles(directory=os.path.join(settings.WEB_ROOT, "css")), name="css")
    app.mount("/js", StaticFiles(directory=os.path.join(settings.WEB_ROOT, "js")), name="js")

    # 静态资源禁用缓存：前端更新后老用户不会命中旧版 js/css，避免页面规则不同步
    @app.middleware("http")
    async def _static_no_cache(request: Request, call_next):
        response = await call_next(request)
        path = request.url.path
        if not path.startswith("/api"):
            response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        return response

    @app.get("/{full_path:path}")
    async def spa_fallback(full_path: str):
        """SPA 兜底：非 API 路径一律返回 index.html（防目录穿越：只允许目录内文件）。
        /api/* 未匹配路由必须显式 404 JSON：此前被本兜底吞成 200+HTML，
        前端 resp.json() 解析失败才知道「接口不存在」，也让 curl 探活误判为存在。"""
        from starlette.responses import FileResponse
        import os as _os
        if full_path == "api" or full_path.startswith("api/"):
            return JSONResponse(status_code=404,
                                content={"code": 404, "msg": "接口不存在"})
        # M5（审计）：超长路径在 realpath/拼接时可能触发上游（nginx/uvicorn）层异常，
        # 先按长度短路；正常 SPA 路由远小于该阈值。
        if len(full_path) >= 4096:
            return JSONResponse(status_code=404, content={"code": 404, "msg": "接口不存在"})
        target = _os.path.realpath(_os.path.join(settings.WEB_ROOT, full_path))
        root = _os.path.realpath(settings.WEB_ROOT)
        if full_path and target.startswith(root + _os.sep) and _os.path.isfile(target):
            return FileResponse(target)
        return FileResponse(_os.path.join(root, "index.html"))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=settings.APP_HOST, port=settings.APP_PORT)
