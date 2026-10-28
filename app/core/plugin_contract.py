# -*- coding: utf-8
"""插件契约：core 只认本文件定义的数据结构与钩子协议，不认识任何具体业务。

一个「插件」(plugin) 可以暴露一个或多个「能力」(Capability)：
  · 能力是计费与权益的最小单位（一个 feature 码 + 一个可售 SKU）；
  · core 在下单 / 支付回调 / 权益核销时，按能力码经注册表找到插件并调用其钩子；
  · 新增业务 = 新增一个插件目录（manifest + service + router），core 零改动。

安全边界（铁律 2）：
  · 插件 service 不得直接写权益/订单/会员/卡券表、不得直接发起收款或结算佣金；
    发权益、收款、计佣只能由 core 完成，插件只通过钩子返回「业务事实」
   （业务快照、biz_key、交付形态、结果数据）。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional, Protocol, runtime_checkable

# 计费时机
# 【接线状态】core 目前只在「下单/支付」这一处计费：services/fulfillment.py 按 product_type
# 与 delivery 分流发放，没有任何代码读 billing_model。因此 BILLING_RUNTIME 只是声明位，
# 设为它不会让每次调用自动扣额（运行期额度模型见 services/quota.py，尚未接进端点）。
BILLING_ORDER = "order"      # 在下单 / 支付链路计费（一份内容一次，交付物可缓存）
BILLING_RUNTIME = "runtime"  # 运行期每次调用扣一次额度（声明位，core 未消费）

# 交付形态
# 【接线状态】core 只读一处：services/fulfillment.order_delivers_report 判 delivery ==
# DELIVERY_REPORT（决定「交付痕迹是否落在 reports 表」，进而决定自助退款判据与报告自愈）。
# 履约的实际发放分支看的是 orders.product_type（membership/single/tool_day/report），
# 不是本枚举。DELIVERY_LIVE 与 DELIVERY_NONE 都没有分支消费——「实时拉取+缓存」由插件
# 自己在钩子里实现，设成 LIVE 不会让 core 替你缓存。
DELIVERY_REPORT = "report"   # 支付后建报告行，后台异步生成（reports 表）
DELIVERY_LIVE = "live"       # 结果实时拉取并缓存（声明位，core 不代为实现）
DELIVERY_NONE = "none"       # 无独立交付物（免费工具 / 仅发放会员或额度）


class PluginError(Exception):
    """插件钩子在入参非法 / 前置数据缺失时抛出；core 据 code/msg 返回统一错误信封。

    code 取 app.core.api.common.ErrorCode 的数值（插件不直接构造响应）。
    """

    def __init__(self, code: int, msg: str, data: Any = None):
        super().__init__(msg)
        self.code = code
        self.msg = msg
        self.data = data


@dataclass
class Capability:
    """单个能力（一个 feature + 一个可售 SKU）。"""
    code: str                                  # 能力/feature 码，权益按它记账，全局唯一
    sku: str                                   # 单次付费 SKU 码
    name: str                                  # 展示名（后台/订单中性类别名，勿用高敏词）
    billing_model: str = BILLING_ORDER
    delivery: str = DELIVERY_REPORT
    single_price_cents: int = 0                # 单次解锁价（分）；manifest 默认价，可被商品表覆盖
    member_included: bool = True               # 会员是否覆盖该能力
    independent_coupon: bool = False           # 独立计费/独立券（会员不覆盖，单独购买）
    member_view_sku: Optional[str] = None      # 会员消费 0 元单 SKU（会员覆盖时必填）
    cost_per_call_cents: int = 0               # 单次上游成本（分），用于预算与防击穿
    daily_budget_cents: int = 0                # 该能力每日上游成本硬上限（分），0=不限（仅零成本可用）
    # 下单时是否依赖「前置计算缓存」（如先计算再购买解读）
    # 【接线状态】core 不读该字段：依赖前置缓存的下单校验由插件在 prepare_order 里自查
    # （api/order.py 只按 result_ref_id 是否解析出 ResultCache 行来决定能否下单）。
    requires_cache: bool = False
    free: bool = False                         # 免费工具（不核销、不可售）

    def __post_init__(self):
        if self.member_included and not self.independent_coupon and not self.free:
            if not self.member_view_sku:
                raise ValueError(
                    f"能力 {self.code}: 会员覆盖且非免费时必须提供 member_view_sku")
        # 独立券只允许运行期无关的下单型（与 scaffold 同口径）
        if self.independent_coupon and self.billing_model != BILLING_ORDER:
            raise ValueError(
                f"能力 {self.code}: independent_coupon 仅支持 billing_model=order")


@dataclass
class PluginManifest:
    """插件自描述：名称 + 能力清单。价源以能力的 single_price_cents 为准。"""
    name: str                                  # 插件包名（目录名）
    display_name: str                          # 后台展示名
    version: str = "1.0.0"
    capabilities: list[Capability] = field(default_factory=list)
    # 会员档位 SKU（该插件若售卖会员）；通用会员也可由 core 统一提供
    membership_skus: dict[str, str] = field(default_factory=dict)  # level -> sku
    # 时长卡 SKU -> 分钟数（可选，插件特有；通用时长卡走 core 配置）
    timepass_sku_minutes: dict[str, int] = field(default_factory=dict)

    def cap_by_sku(self, sku: str) -> Optional[Capability]:
        for c in self.capabilities:
            if c.sku == sku or c.member_view_sku == sku:
                return c
        return None

    def cap_by_code(self, code: str) -> Optional[Capability]:
        for c in self.capabilities:
            if c.code == code:
                return c
        return None


@dataclass
class OrderPrep:
    """prepare_order 钩子返回的业务事实（core 据此建单）。"""
    biz_data: dict[str, Any]
    input_snapshot: Any = None
    result_ref_id: Optional[int] = None
    biz_key: Optional[str] = None


@dataclass
class PaidResult:
    """on_paid 钩子返回的履约事实（core 据此发权益 / 决定是否触发后台生成）。"""
    biz_key: Optional[str] = None
    need_report_task: bool = False
    expire_at: Any = None                      # datetime 或 None（按天类能力的到期时刻）
    extra: dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class PluginService(Protocol):
    """插件 service 必须实现的钩子（按需实现；core 对缺失钩子按 no-op 处理）。"""

    async def prepare_order(self, cap: Capability, raw: dict, user: Any,
                            db: Any) -> OrderPrep: ...

    async def on_paid(self, cap: Capability, order: Any, db: Any) -> PaidResult: ...

    def on_refund(self, cap: Capability, order: Any, db: Any) -> Any: ...

    def derive_check_biz_key(self, cap: Capability, sides: Any,
                             relation: Any) -> Optional[str]:
        """可选：权益校验时由服务端按 sides 派生 biz_key（无需插件实现，返回 None 即可）。"""
        return None

    def generation_task(self) -> Optional[Any]:
        """可选：返回后台生成协程 f(order_id)（报告型能力用）；无异步生成的插件返回 None。"""
        return None

    def lunar_converter(self) -> Optional[Any]:
        """可选：返回农历转公历 callable f(y,m,d)->date；不支持的插件返回 None。"""
        return None

    async def on_user_erase(self, user: Any, db: Any) -> None:
        """可选：注销账号时清理插件专属业务数据（如业务档案）。
        core 通用表（反馈/报告/权益/会员/收藏/结果缓存）由 core 自管，插件只清自己的表。"""
        return None

    async def favorite_types(self) -> list[str]:
        """可选：本插件可被收藏的业务 item_type（如 ['archive']）。"""
        return []

    async def describe_favorite(self, item_type: str, item_id: int, user: Any,
                                db: Any) -> Optional[tuple]:
        """可选：收藏时由服务端取快照，返回 (title, sub, payload)；不存在/无权返回 None。"""
        return None

    async def favorite_alive(self, item_type: str, item_ids: list[int],
                             db: Any) -> set:
        """可选：返回仍存活（未软删）的 item_id 集合，用于收藏列表 source_alive。"""
        return set()

    async def admin_user_dump(self, user_id: int, db: Any) -> dict:
        """可选：后台用户详情中贡献插件自己的业务数据片段（key -> 列表/对象）。"""
        return {}
