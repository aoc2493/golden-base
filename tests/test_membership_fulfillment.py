"""会员档位端到端履约回归（P0 防线）。

覆盖「钱付了、会员没到」这条最贵的路径：底座 vip_* 档位能下单、能收到回调，
但履约要经 membership.level_of_sku 反查出档位。此前该函数只认插件
manifest.membership_skus，而底座档位商品写死在 main._seed_base_data 里，两边一脱钩，
grant_membership 直接抛 ValueError("非会员SKU")，订单卡在未履约、用户已扣款。

全链路不 mock：模拟支付回调 → _mark_order_paid（CAS 抢履约权）→ fulfill_paid_order
→ grant_membership，再断言用户真的是 VIP。
"""
from datetime import datetime
from decimal import Decimal

import pytest
from sqlalchemy import select

from app.config import settings
from app.core.models import Order, Product, User
from app.core.services.membership import get_member_status, level_of_sku

BASE_TIERS = {"vip_month": "month", "vip_year": "year", "vip_lifetime": "lifetime"}


async def _pay(db, order, trade_no):
    """走真实回调收口函数完成支付与履约，返回 _mark_order_paid 的结果。"""
    from fastapi import BackgroundTasks

    from app.core.api.payment import _mark_order_paid

    return await _mark_order_paid(db, order, trade_no, BackgroundTasks(),
                                  amount_paid=order.amount)


def test_base_tier_skus_resolve_to_level():
    """底座三个档位 SKU 必须都能反查出档位——不依赖任何插件是否声明 membership_skus。"""
    for sku, level in BASE_TIERS.items():
        assert level_of_sku(sku) == level, f"{sku} 应解析为 {level}"


async def test_seeded_membership_products_are_fulfillable(db):
    """种子写出的会员商品与反查表同源：库里每一个在售会员档都能被履约认出。

    这条断言同时钉住「改配置码而忘改种子」和「加档位而忘登记」两种漂移方向。
    """
    from sqlalchemy import select

    from app.main import _seed_base_data

    await _seed_base_data(db)
    products = (await db.execute(select(Product).where(
        Product.product_type == "membership", Product.enabled == 1))).scalars().all()
    assert products, "底座未播种会员商品，会员链路无从测试"
    for p in products:
        assert level_of_sku(p.sku_code), f"在售会员商品 {p.sku_code} 反查不到档位"
        assert p.price and float(p.price) > 0, f"{p.sku_code} 定价缺失"


async def test_paid_membership_order_is_fulfilled(db):
    """月卡付款后：订单必须 completed、fulfilled_at 落库、用户成为 month 档 VIP。"""
    user = User(phone="13900000011", nickname="会员买家")
    db.add(user)
    await db.flush()
    order = Order(order_no="VIP-1", user_id=user.id, product_name="月卡会员",
                  sku_code="vip_month", product_type="membership",
                  amount=Decimal("99.00"), status="pending")
    db.add(order)
    await db.flush()

    result = await _pay(db, order, "TRADE-VIP-1")
    assert result.get("paid") is True, f"回调被拒: {result}"

    st = await get_member_status(db, user.id)
    assert st["is_vip"] is True, f"已付款但未成为 VIP: {st}"
    assert st["level"] == "month"
    assert order.status == "completed" and order.fulfilled_at is not None


async def test_membership_tiers_differ_by_days(db):
    """年卡比月卡给的天数多：档位码若解析错档，这里会立刻暴露。"""
    users = []
    for idx, (sku, level) in enumerate((("vip_month", "month"), ("vip_year", "year"))):
        u = User(phone=f"1390000002{idx}", nickname=f"买家{level}")
        db.add(u)
        await db.flush()
        users.append(u)
        o = Order(order_no=f"VIP-D{idx}", user_id=u.id, product_name="会员",
                  sku_code=sku, product_type="membership",
                  amount=Decimal("99.00"), status="pending")
        db.add(o)
        await db.flush()
        assert (await _pay(db, o, f"TRADE-D{idx}")).get("paid") is True

    now = datetime.now()
    st_month = await get_member_status(db, users[0].id, now=now)
    st_year = await get_member_status(db, users[1].id, now=now)
    assert st_month["level"] == "month" and st_year["level"] == "year"
    assert st_year["expire_at"] > st_month["expire_at"], "年卡到期时刻应晚于月卡"
    assert st_year["days_remain"] > st_month["days_remain"], "年卡剩余天数应多于月卡"
    assert st_year["days_remain"] >= 360, f"年卡未按 365 天发放: {st_year['days_remain']}"


async def test_duplicate_membership_callback_grants_once(db):
    """同一会员单重复回调不得二次顺延时长（幂等闸必须生效）。"""
    user = User(phone="13900000012", nickname="重复回调买家")
    db.add(user)
    await db.flush()
    order = Order(order_no="VIP-2", user_id=user.id, product_name="月卡会员",
                  sku_code="vip_month", product_type="membership",
                  amount=Decimal("99.00"), status="pending")
    db.add(order)
    await db.flush()

    assert (await _pay(db, order, "TRADE-VIP-2")).get("paid") is True
    first = await get_member_status(db, user.id)
    expire1 = first["expire_at"]
    assert expire1 is not None

    replay = await _pay(db, order, "TRADE-VIP-2")
    assert replay.get("idempotent") is True, f"重复回调未走幂等分支: {replay}"
    second = await get_member_status(db, user.id)
    assert second["expire_at"] == expire1, "重复回调导致会员时长二次顺延"


async def test_startup_gate_blocks_unregistered_membership_sku(db, monkeypatch):
    """启动门禁：在售会员商品反查不到档位时，生产拒绝启动、非生产只告警、下架不拦。

    这条门禁是给上面的 P0 兜底的：档位码与种子一旦再次脱钩，故障会在启动时就暴露，
    而不是等用户付了钱才发现权益没到。
    """
    from app.main import _check_membership_products, _seed_base_data

    await _seed_base_data(db)
    await db.commit()
    await _check_membership_products(db)          # 底座自家档位必须全部放行

    db.add(Product(sku_code="vip_quarter", product_type="membership", feature="vip",
                   name="季卡", price="49.00", enabled=1))
    await db.commit()

    monkeypatch.setattr(settings, "APP_ENV", "production")
    with pytest.raises(RuntimeError, match="反查不到档位"):
        await _check_membership_products(db)

    # 非生产：同样的数据只记 ERROR，不阻断（否则本地演示环境起不来）
    monkeypatch.setattr(settings, "APP_ENV", "development")
    await _check_membership_products(db)

    # 下架（enabled=0）的坏档位不在售，不该拦启动
    row = (await db.execute(select(Product).where(
        Product.sku_code == "vip_quarter"))).scalar_one()
    row.enabled = 0
    await db.commit()
    monkeypatch.setattr(settings, "APP_ENV", "production")
    await _check_membership_products(db)
