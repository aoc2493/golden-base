from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.database import get_db
from app.core.models import SystemConfig, User
from app.core.auth import get_current_user
from app.core.api.common import success
from app.plugins import registry
import json

router = APIRouter(prefix="/system", tags=["系统配置"])

# T4：匿名可访问的公开配置白名单（主题、前端功能开关）；佣金比例等内部运营配置不公开
_PUBLIC_KEYS = {"paid_reports_enabled", "refund_enabled", "theme", "result_cache_days",
                "distribution_enabled", "announcement", "vip_benefits"}

# 仅登录可见、且经确认不含运营敏感数据的配置项。新增必须逐项显式登记，
# 不得改成“除某些 key 外全部返回”的反向黑名单：黑名单永远会漏掉后来新增的敏感项。
_INTERNAL_KEYS: set = set()

# 会员权益文案默认值由插件经注册表聚合（registry.default_vip_benefits），
# core 不写死任何业务内容；让「后端下发」成为唯一来源，运营改文案不必发版，
# 也可由系统配置表同名键覆盖。前端按「字符串数组」渲染，元素必须是字符串。


# ============ 能力位（体验走查修复 P0/P1）============
# 站点多处入口的可用性取决于运行期是否接了外部通道，此前前端一律照常展示：
#   · 注册页摆「验证码 *」+「发送验证码」，但邮件未接入 —— 点一下就把该邮箱的
#     注册通道堵死 10 分钟（验证码落了 Redis 却永远收不到）；
#   · 充值区摆 ¥50/¥100/¥200/¥500/¥1000 五档 + 确认充值，但商户凭据未配 ——
#     填完点下去才被告知「暂未开通」。
# 统一由此接口下发两个布尔位，前端按位收起入口并给准确文案；系统配置表写入
# 同名键可人工覆盖（例如灰度关闭某项）。
# 两个探测都在函数内延迟导入并兜底 False：任一侧导入失败只等于「该能力不可用」，
# 绝不能把公开配置接口打成 500（首页/注册页/开发者中心都依赖它）。


def _email_verify_enabled() -> bool:
    try:
        from app.core.api.auth import HAS_EMAIL
        return bool(HAS_EMAIL)
    except Exception:
        return False


def _api_payment_enabled() -> bool:
    try:
        from app.core.utils.payment import wechat_pay, alipay
        return bool(wechat_pay.is_configured() or alipay.is_configured())
    except Exception:
        return False


def _apply_capability_bits(public: dict) -> dict:
    public.setdefault("email_verify_enabled", _email_verify_enabled())
    public.setdefault("api_payment_enabled", _api_payment_enabled())
    return public


async def _load_all(db: AsyncSession) -> dict:
    configs = (await db.execute(select(SystemConfig))).scalars().all()
    data = {}
    for cfg in configs:
        value = cfg.config_value
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except (json.JSONDecodeError, TypeError):
                pass
        data[cfg.config_key] = value
    return data


@router.get("/config")
async def get_public_config(db: AsyncSession = Depends(get_db)):
    """公开配置（无需登录）：仅返回白名单内的非敏感项（T4）"""
    data = await _load_all(db)
    public = {k: v for k, v in data.items() if k in _PUBLIC_KEYS}
    public.setdefault("paid_reports_enabled", True)
    public.setdefault("refund_enabled", True)
    public.setdefault("distribution_enabled", True)
    public.setdefault("theme", {"primary_color": "#8B4513", "accent_color": "#D2691E", "danger_color": "#e64340"})
    # announcement / vip_benefits 虽在 _PUBLIC_KEYS 白名单内，但 system_configs 表里
    # 一直没有这两行，实测 /system/config 从不返回它们：首页公告永远不弹，会员权益文案
    # 只能吃前端硬编码的 fallbackVipBenefits（改文案要发版）。补上与前端一致的默认值，
    # 运营往表里写入同名键即可覆盖，前端兜底保留但不再是唯一来源。
    public.setdefault("announcement", "")
    public.setdefault("vip_benefits", registry.default_vip_benefits())
    _apply_capability_bits(public)
    return success(public)


@router.get("/config/internal")
async def get_internal_config(db: AsyncSession = Depends(get_db),
                              user: User = Depends(get_current_user)):
    """登录后配置：与公开接口同样只返回白名单内的非敏感项。
    原实现直接返回整张 system_configs 表，绕过了上面 T4 白名单：
    任意登录用户（注册零门槛，设备码即可拿到 token）就能读到后续新增的任何内部项，
    例如佣金比例、提现门槛、结算周期、客服话术等运营参数（改价/刷佣的前置情报）。
    全仓前后端均无任何调用方依赖本接口的“全量”语义，收紧为零风险。
    如后续确有仅登录可见的配置需求，请往 _INTERNAL_KEYS 里逐项显式登记，不要改回全量返回。"""
    data = await _load_all(db)
    allowed = _PUBLIC_KEYS | _INTERNAL_KEYS
    internal = {k: v for k, v in data.items() if k in allowed}
    internal.setdefault("paid_reports_enabled", True)
    internal.setdefault("refund_enabled", True)
    _apply_capability_bits(internal)
    return success(internal)
