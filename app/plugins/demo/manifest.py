# -*- coding: utf-8 -*-
"""Demo 插件的能力声明。

能力码全局唯一，SKU 是下单时唯一的价源（商品表由 service.seed_data 同步）。
"""
from app.core.plugin_contract import (
    BILLING_ORDER,
    DELIVERY_NONE,
    Capability,
    PluginManifest,
)

DEMO_FEATURE = "demo.echo"
DEMO_SKU = "demo_echo"

MANIFEST = PluginManifest(
    name="demo",
    display_name="Demo 能力",
    version="1.0.0",
    capabilities=[
        Capability(
            code=DEMO_FEATURE,
            sku=DEMO_SKU,
            name="演示回声",
            billing_model=BILLING_ORDER,
            delivery=DELIVERY_NONE,
            single_price_cents=100,
            # 独立计费：会员/时长卡不覆盖，必须单次购买
            member_included=False,
            independent_coupon=True,
            cost_per_call_cents=0,
        ),
    ],
)
