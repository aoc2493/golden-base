"""并发重复投递的资金链路：状态流转必须用「带条件的原子 UPDATE」抢占权利。

这两条用例证明的是同一类缺陷：注释与文档都写了「幂等/并发安全」，但幂等闸读的是
本 session 内存里的旧值。回调重复投递时两条链路各自的 session 都读到「未履约/未退款」，
双双穿过内存闸 → 会员天数二次顺延、佣金二次冲回、权益二次发放。

写法说明（为什么不是 asyncio.gather）：真实并发要 MySQL 行锁才复现得干净，本机没有。
但缺陷的充分条件不是「同时执行」，而是「B 拿着陈旧的内存判定进入 CAS 之前的那步 SELECT」——
所以这里显式造出陈旧状态：B 先读到订单/退款单，然后结束自己的事务（expire_on_commit=False
让实例保留刚读到的值），A 完成并提交，B 再执行。若实现只用内存闸，B 必然二次履约/二次回收；
用条件 UPDATE 抢占，B 的 WHERE 不再匹配 → rowcount=0 → 幂等返回。
"""
from datetime import datetime
from decimal import Decimal

import pytest_asyncio
from fastapi import BackgroundTasks
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

import app.core.database  # noqa: F401  副作用导入：注册 SQLite 方言补丁（BigInteger→INTEGER）
from app.core.api.payment import _mark_order_paid
from app.core.models import Base, Order, Refund, User
from app.core.services import refund_state

AMOUNT = Decimal("39.90")


@pytest_asyncio.fixture
async def factory(tmp_path):
    """独立文件库 + 多个真实连接：两个 session 必须各占一条连接才谈得上并发投递。

    不能用 conftest 的 :memory: + StaticPool——所有 session 共用一条连接，
    第二个事务永远看得见第一个的未提交写入，测不出「提交后才可见」的抢占语义。
    """
    engine = create_async_engine(
        f"sqlite+aiosqlite:///{(tmp_path / 'conc.db').as_posix()}",
        connect_args={"check_same_thread": False, "timeout": 15})
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    await engine.dispose()


async def _seed_order(s):
    user = User(phone="13900000041", nickname="并发者")
    s.add(user)
    await s.flush()
    order = Order(order_no="CC-PAY-1", user_id=user.id, sku_code="vip_month",
                  product_name="月度会员", product_type="membership",
                  amount=AMOUNT, status="pending", pay_channel="wechat")
    s.add(order)
    await s.flush()
    return order


async def test_second_payment_callback_does_not_fulfil_again(factory, monkeypatch):
    """两条并发回调：只有抢到 status 翻转的那条履约。"""
    calls = []

    async def fake_fulfill(db, order):
        calls.append(order.order_no)
        return {"fulfilled": True}

    monkeypatch.setattr("app.core.api.payment.fulfill_paid_order", fake_fulfill)

    async with factory() as loser, factory() as winner, factory() as seed:
        order = await _seed_order(seed)
        await seed.commit()

        loser_order = (await loser.execute(
            select(Order).where(Order.id == order.id))).scalar_one()
        await loser.commit()  # 结束事务但保留内存值：此刻 loser 以为订单仍是 pending

        winner_order = (await winner.execute(
            select(Order).where(Order.id == order.id))).scalar_one()
        r1 = await _mark_order_paid(winner, winner_order, "TXN-1",
                                    BackgroundTasks(), amount_paid=AMOUNT)
        await winner.commit()
        assert r1["paid"] and r1.get("rowcount") == 1

        r2 = await _mark_order_paid(loser, loser_order, "TXN-1",
                                    BackgroundTasks(), amount_paid=AMOUNT)
        assert r2.get("idempotent") is True, f"陈旧回调被当作首次履约放行: {r2}"
        assert r2.get("rowcount") == 0

        assert calls == ["CC-PAY-1"], f"重复投递履约了 {len(calls)} 次: {calls}"


async def test_second_refund_success_does_not_reclaim_again(factory, monkeypatch):
    """退款成功投递两次：权益回收/冲佣只执行一次。"""
    calls = []

    async def fake_revoke(db, order):
        calls.append(order.order_no)
        return None

    monkeypatch.setattr(refund_state, "revoke_refunded_order", fake_revoke)

    async with factory() as loser, factory() as winner, factory() as seed:
        user = User(phone="13900000042", nickname="退款并发")
        seed.add(user)
        await seed.flush()
        order = Order(order_no="CC-RF-1", user_id=user.id, sku_code="demo_echo",
                      product_name="报告", product_type="report", amount=AMOUNT,
                      status="refund_pending", pay_channel="wechat",
                      paid_at=datetime.now(), fulfilled_at=datetime.now())
        seed.add(order)
        await seed.flush()
        refund = Refund(order_id=order.id, user_id=user.id, refund_no="CC-RFNO-1",
                        reason="用户申请", status="processing")
        seed.add(refund)
        await seed.commit()

        loser_refund = (await loser.execute(
            select(Refund).where(Refund.id == refund.id))).scalar_one()
        await loser.commit()  # loser 内存里这条退款单仍是 processing

        winner_refund = (await winner.execute(
            select(Refund).where(Refund.id == refund.id))).scalar_one()
        assert await refund_state.apply_channel_refund_status(
            winner, winner_refund, "SUCCESS", source="test") == "refunded"
        await winner.commit()

        again = await refund_state.apply_channel_refund_status(
            loser, loser_refund, "SUCCESS", source="test")
        assert again == "refunded"
        assert calls == ["CC-RF-1"], f"重复投递回收了 {len(calls)} 次: {calls}"


async def test_two_refund_rows_on_one_order_reclaim_only_once(factory, monkeypatch):
    """同一订单的两条不同退款单各自抢到退款单行，仍只能回收一次权益。

    refunds.order_id 没有唯一约束（用户申请→驳回→再申请/管理员兜底会留下多行），
    只按退款单行 CAS 拦不住这种形态：两条链路各改各的行、都抢到成功，
    于是 revoke_refunded_order 执行两次——会员天数二次扣减、佣金二次冲回。
    唯一能钉住它的是订单级 CAS（谁把订单翻成 refunded 谁回收）。
    """
    calls = []

    async def fake_revoke(db, order):
        calls.append(order.order_no)
        return None

    monkeypatch.setattr(refund_state, "revoke_refunded_order", fake_revoke)

    async with factory() as s1, factory() as s2, factory() as seed:
        user = User(phone="13900000043", nickname="双退款单")
        seed.add(user)
        await seed.flush()
        order = Order(order_no="CC-RF-2", user_id=user.id, sku_code="demo_echo",
                      product_name="报告", product_type="report", amount=AMOUNT,
                      status="refund_pending", pay_channel="wechat",
                      paid_at=datetime.now(), fulfilled_at=datetime.now())
        seed.add(order)
        await seed.flush()
        seed.add_all([
            Refund(order_id=order.id, user_id=user.id, refund_no="CC-RFNO-A",
                   reason="用户申请", status="processing"),
            Refund(order_id=order.id, user_id=user.id, refund_no="CC-RFNO-B",
                   reason="后台兜底", status="processing")])
        await seed.commit()

        ra = (await s1.execute(select(Refund).where(Refund.refund_no == "CC-RFNO-A"))).scalar_one()
        rb = (await s2.execute(select(Refund).where(Refund.refund_no == "CC-RFNO-B"))).scalar_one()
        # 两条链路都已在「订单尚未 refunded」的时刻读完自己的退款单行（都以为是 processing）
        await s1.commit()
        await s2.commit()
        assert await refund_state.apply_channel_refund_status(
            s1, ra, "SUCCESS", source="test") == "refunded"
        await s1.commit()
        assert await refund_state.apply_channel_refund_status(
            s2, rb, "SUCCESS", source="test") == "refunded"
        await s2.commit()

        assert calls == ["CC-RF-2"], f"同订单两条退款单各回收一次: {calls}"
