"""启动种子必须「只补不覆盖」。

启动种子必须只补缺失行，不能把会员档位的名称、价格、排序按代码值同步回库，
否则运营改过的价格会在重启后被覆盖，主动下架的档位也会被重新上架。
这里锁死两条不变量：
  · 运营改过的商品行，重启后一个字都不变；
  · 重启不会产生重复行（补插按 sku_code 判存在性）。
"""
from decimal import Decimal

from sqlalchemy import select

from app.core.models import Product, SystemConfig
from app.main import _seed_base_data


async def test_seed_does_not_overwrite_operator_changes(db):
    await _seed_base_data(db)

    row = (await db.execute(
        select(Product).where(Product.sku_code == "vip_month"))).scalar_one()
    row.price = Decimal("199.00")
    row.name = "运营自定义月卡"
    row.enabled = 0
    await db.commit()

    await _seed_base_data(db)   # 模拟一次重启

    rows = (await db.execute(
        select(Product).where(Product.sku_code == "vip_month"))).scalars().all()
    assert len(rows) == 1, "重启后出现重复商品行"
    assert rows[0].price == Decimal("199.00")
    assert rows[0].name == "运营自定义月卡"
    assert rows[0].enabled == 0

    total = (await db.execute(
        select(Product).where(Product.product_type == "membership"))).scalars().all()
    assert len(total) == 3, "重复执行种子导致会员档位重复插入"


async def test_seed_fills_only_missing_config_keys(db):
    # 运营只手工加过一条公告：其余缺省键仍应被补齐，公告本身不得被覆盖
    db.add(SystemConfig(config_key="announcement", config_value="运营公告：国庆正常服务"))
    await db.commit()

    await _seed_base_data(db)

    cfg = {c.config_key: c for c in (
        await db.execute(select(SystemConfig))).scalars().all()}
    assert cfg["announcement"].config_value == "运营公告：国庆正常服务"
    for key in ("paid_reports_enabled", "refund_enabled", "distribution_enabled", "vip_benefits"):
        assert key in cfg, f"缺省配置 {key} 未被补齐"
