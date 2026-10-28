# -*- coding: utf-8 -*-
"""插件注册表：启动时扫描 app/plugins/ 下的插件包，聚合能力清单。

约定每个插件目录（如 plugins/<你的业务>/）：
  · manifest.py  —— 必须，暴露 MANIFEST: PluginManifest
  · service.py   —— 必须，暴露 service（实现 prepare_order / on_paid / on_refund 钩子）
  · api/*.py     —— 可选，每个模块暴露一个 APIRouter（也可用顶层 router.py）

core 与 main 只通过本注册表访问插件，不 import 任何具体插件名；
新增业务 = 新增一个插件目录，注册表自动发现，core / main 零改动。
"""
from __future__ import annotations

import importlib
import pkgutil
from dataclasses import dataclass, field
from typing import Any, Optional

from app.core.plugin_contract import (
    Capability,
    PluginManifest,
)


@dataclass
class PluginEntry:
    name: str
    manifest: PluginManifest
    service: Any
    routers: list = field(default_factory=list)

    def cap_by_sku(self, sku: str) -> Optional[Capability]:
        return self.manifest.cap_by_sku(sku)

    def cap_by_code(self, code: str) -> Optional[Capability]:
        return self.manifest.cap_by_code(code)


class _Registry:
    def __init__(self):
        self.plugins: dict[str, PluginEntry] = {}
        self._discovered = False

    # ---------- 发现与注册 ----------
    def discover(self) -> None:
        if self._discovered:
            return
        import app.plugins as pkg
        for mod_info in pkgutil.iter_modules(pkg.__path__):
            if not mod_info.ispkg or mod_info.name.startswith("_"):
                continue
            self._load_plugin(mod_info.name)
        self._discovered = True

    def _load_plugin(self, name: str) -> None:
        try:
            manifest_mod = importlib.import_module(f"app.plugins.{name}.manifest")
            service_mod = importlib.import_module(f"app.plugins.{name}.service")
        except ModuleNotFoundError as exc:
            raise RuntimeError(
                f"插件 {name} 缺少 manifest.py 或 service.py: {exc}") from exc
        manifest: PluginManifest = getattr(manifest_mod, "MANIFEST", None)
        service = getattr(service_mod, "service", None)
        if not isinstance(manifest, PluginManifest):
            raise RuntimeError(f"插件 {name}: manifest.py 必须暴露 MANIFEST: PluginManifest")
        if service is None:
            raise RuntimeError(f"插件 {name}: service.py 必须暴露 service 对象")
        if manifest.name != name:
            raise RuntimeError(
                f"插件 {name}: MANIFEST.name='{manifest.name}' 必须与目录名一致")

        routers = self._collect_routers(name)
        entry = PluginEntry(name=name, manifest=manifest, service=service, routers=routers)
        self._validate(entry)
        self.plugins[name] = entry

    def _collect_routers(self, name: str) -> list:
        routers = []
        # 顶层 router.py
        try:
            top = importlib.import_module(f"app.plugins.{name}.router")
            r = getattr(top, "router", None)
            if r is not None:
                routers.append(r)
        except ModuleNotFoundError:
            pass
        # api/ 包下所有模块的 router
        try:
            api_pkg = importlib.import_module(f"app.plugins.{name}.api")
            for mod_info in pkgutil.iter_modules(api_pkg.__path__):
                mod = importlib.import_module(f"app.plugins.{name}.api.{mod_info.name}")
                r = getattr(mod, "router", None)
                if r is not None:
                    routers.append(r)
        except ModuleNotFoundError:
            pass
        return routers

    def _validate(self, entry: PluginEntry) -> None:
        seen_codes, seen_skus, seen_view = set(), set(), set()
        for cap in entry.manifest.capabilities:
            if cap.code in seen_codes:
                raise RuntimeError(f"插件 {entry.name}: 能力码重复 {cap.code}")
            seen_codes.add(cap.code)
            if cap.sku in seen_skus:
                raise RuntimeError(f"插件 {entry.name}: SKU 重复 {cap.sku}")
            seen_skus.add(cap.sku)
            if cap.member_view_sku:
                if cap.member_view_sku in seen_view:
                    raise RuntimeError(
                        f"插件 {entry.name}: 会员消费 SKU 重复 {cap.member_view_sku}")
                seen_view.add(cap.member_view_sku)
            # 可售能力必须正价（免费 / 会员档位除外）
            if not cap.free and cap.single_price_cents <= 0:
                raise RuntimeError(
                    f"插件 {entry.name}: 能力 {cap.code} 单次价必须为正（或标记 free=True）")
            # 付费上游必须有成本上限，防止预算被击穿（零成本能力除外）
            if cap.cost_per_call_cents > 0 and cap.daily_budget_cents <= 0:
                raise RuntimeError(
                    f"插件 {entry.name}: 能力 {cap.code} 有上游成本却未设 daily_budget_cents")
            if cap.independent_coupon and cap.member_included:
                raise RuntimeError(
                    f"插件 {entry.name}: 能力 {cap.code} 独立券必须 member_included=False")
        # 跨插件全局唯一
        for other in self.plugins.values():
            for cap in entry.manifest.capabilities:
                if other.cap_by_code(cap.code):
                    raise RuntimeError(f"能力码跨插件冲突: {cap.code}")
                if other.cap_by_sku(cap.sku):
                    raise RuntimeError(f"SKU 跨插件冲突: {cap.sku}")

    # ---------- 查询 ----------
    def get(self, name: str) -> PluginEntry:
        return self.plugins[name]

    def cap_by_sku(self, sku: str) -> tuple[Optional[PluginEntry], Optional[Capability]]:
        for e in self.plugins.values():
            cap = e.cap_by_sku(sku)
            if cap:
                return e, cap
        return None, None

    def cap_by_code(self, code: str) -> tuple[Optional[PluginEntry], Optional[Capability]]:
        for e in self.plugins.values():
            cap = e.cap_by_code(code)
            if cap:
                return e, cap
        return None, None

    def membership_level_by_sku(self, sku: str) -> tuple[Optional[PluginEntry], Optional[str]]:
        for e in self.plugins.values():
            for level, ms in e.manifest.membership_skus.items():
                if ms == sku:
                    return e, level
        return None, None

    def match_path(self, path: str) -> tuple[Optional[PluginEntry], Optional[Capability]]:
        """按请求路径反查能力（用于运行期权益核销）。匹配最长 router 前缀。"""
        best = None
        best_len = 0
        for e in self.plugins.values():
            for r in e.routers:
                prefix = getattr(r, "prefix")
                if prefix and path.startswith(prefix) and len(prefix) > best_len:
                    best, best_len = e, len(prefix)
        return (best, None) if best else (None, None)

    # ---------- 聚合视图（供 core 通用模块使用，core 不硬编码任何业务码）----------
    def sku_to_feature(self) -> dict[str, str]:
        out = {}
        for e in self.plugins.values():
            for c in e.manifest.capabilities:
                out[c.sku] = c.code
        return out

    def feature_names(self) -> dict[str, str]:
        out = {}
        for e in self.plugins.values():
            for c in e.manifest.capabilities:
                out[c.code] = c.name
        return out

    def standalone_features(self) -> set[str]:
        """独立计费 / 独立券能力（会员与时长卡不覆盖）。"""
        out = set()
        for e in self.plugins.values():
            for c in e.manifest.capabilities:
                if c.independent_coupon:
                    out.add(c.code)
        return out

    def member_view_skus(self) -> set[str]:
        out = set()
        for e in self.plugins.values():
            for c in e.manifest.capabilities:
                if c.member_view_sku:
                    out.add(c.member_view_sku)
        return out

    def member_covered_single_skus(self) -> set[str]:
        out = set()
        for e in self.plugins.values():
            for c in e.manifest.capabilities:
                if c.member_included and not c.independent_coupon and not c.free:
                    out.add(c.sku)
        return out

    def view_sku_to_single(self) -> dict[str, str]:
        out = {}
        for e in self.plugins.values():
            for c in e.manifest.capabilities:
                if c.member_view_sku:
                    out[c.member_view_sku] = c.sku
        return out

    def all_single_skus(self) -> set[str]:
        return {c.sku for e in self.plugins.values() for c in e.manifest.capabilities}

    def timepass_sku_minutes(self) -> dict[str, int]:
        out = {}
        for e in self.plugins.values():
            out.update(e.manifest.timepass_sku_minutes)
        return out

    def lunar_converter(self):
        """聚合：返回第一个提供农历转公历能力的插件 callable f(y,m,d)->date；没有则 None。"""
        for e in self.plugins.values():
            try:
                fn = e.service.lunar_converter()
            except Exception:
                fn = None
            if fn:
                return fn
        return None

    async def erase_user_data(self, user: Any, db: Any) -> None:
        """注销聚合：遍历插件清理其专属业务数据（core 通用表由 core 自管）。
        钩子失败不阻断注销（与 core 注销容错同口径），但不静默吞掉——记录由调用方处理。"""
        for e in self.plugins.values():
            fn = getattr(e.service, "on_user_erase", None)
            if fn:
                await fn(user, db)

    async def favorite_provider(self, item_type: str):
        """返回声明可收藏该 item_type 的插件 entry；core 自有类型（report）返回 None。"""
        for e in self.plugins.values():
            fn = getattr(e.service, "favorite_types", None)
            if fn:
                try:
                    types = await fn()
                except Exception:
                    types = []
                if item_type in types:
                    return e
        return None

    async def admin_user_extra_data(self, user_id: int, db: Any) -> dict:
        """后台用户详情：聚合各插件贡献的业务数据片段（core 通用 entitlements 由 core 自管）。"""
        out: dict = {}
        for e in self.plugins.values():
            fn = getattr(e.service, "admin_user_dump", None)
            if fn:
                try:
                    out.update(await fn(user_id, db))
                except Exception:
                    pass
        return out

    def default_vip_benefits(self) -> list:
        """聚合各插件自描述的会员权益默认文案（core 公开配置经此取，不写死业务内容）。"""
        out: list = []
        for e in self.plugins.values():
            try:
                bs = e.service.vip_benefits()
            except Exception:
                bs = None
            if bs:
                out.extend(bs)
        return out


# 全局单例
registry = _Registry()


def discover() -> None:
    registry.discover()
