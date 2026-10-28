# -*- coding: utf-8 -*-
"""Demo 插件钩子实现。

core 只通过钩子拿「业务事实」：下单快照、biz_key、交付形态；
发权益、收款、计佣一律由 core 完成，插件不直接写权益/订单表。
"""
import hashlib
import json

from sqlalchemy import select

from app.core.api.common import ErrorCode
from app.core.models import Product
from app.core.plugin_contract import OrderPrep, PaidResult, PluginError
from app.plugins.demo.manifest import DEMO_SKU

MAX_TEXT_LEN = 200


def echo_biz_key(text: str) -> str:
    """同一段文本对应同一把权益钥匙（内容级去重）。"""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:32]


def _read_text(raw: dict) -> str:
    text = str(((raw or {}).get("biz_data") or {}).get("text") or "").strip()
    if not text:
        raise PluginError(ErrorCode.PARAM_ERROR, "请输入要回显的文本")
    if len(text) > MAX_TEXT_LEN:
        raise PluginError(ErrorCode.PARAM_ERROR, f"文本不能超过 {MAX_TEXT_LEN} 个字符")
    return text


class DemoService:
    async def prepare_order(self, cap, raw, user, db) -> OrderPrep:
        text = _read_text(raw)
        return OrderPrep(
            biz_data={"text": text},
            input_snapshot={"text": text},
            biz_key=echo_biz_key(text),
        )

    async def on_paid(self, cap, order, db) -> PaidResult:
        snapshot = order.input_snapshot or {}
        if isinstance(snapshot, str):
            snapshot = json.loads(snapshot)
        text = str(snapshot.get("text") or "")
        return PaidResult(biz_key=echo_biz_key(text))

    def on_refund(self, cap, order, db):
        # 权益由 core 按订单撤销，这里无需额外回收
        return None

    def derive_check_biz_key(self, cap, sides, relation):
        if sides:
            return echo_biz_key(str(sides[0]))
        return None

    def generation_task(self):
        return None

    def lunar_converter(self):
        return None

    def vip_benefits(self) -> list:
        return []

    async def seed_data(self, db) -> None:
        """把能力对应的可售商品写入 products 表（价源仍以 manifest 为准）。"""
        existing = (await db.execute(
            select(Product).where(Product.sku_code == DEMO_SKU)
        )).scalar_one_or_none()
        if existing is not None:
            return
        db.add(Product(
            sku_code=DEMO_SKU,
            product_type="single",
            feature="demo.echo",
            name="演示回声",
            description="输入一段文本，支付后即可回显。用于验证登录→下单→支付→权益全链路。",
            price="1.00",
            refund_rule="演示商品，支付后不退",
            sort_order=10,
            enabled=1,
        ))
        await db.flush()


service = DemoService()
