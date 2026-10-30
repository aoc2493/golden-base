"""生产可用性与资金安全回归测试。"""
from datetime import datetime, timedelta
from decimal import Decimal
from pathlib import Path
import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

import app.core.database  # noqa: F401 - 注册 SQLite BigInteger 补丁
from app.config import settings
from app.core.api.common import redis_acquire_lock
from app.core.models import Base, Order, Product, Refund, Report, User
from app.core.tasks import scheduler
from app.core.utils.payment import RefundResult

ROOT = Path(__file__).resolve().parents[1]


async def _register(client) -> str:
    email = f"safety-test-{uuid.uuid4().hex[:10]}@example.com"
    resp = await client.post("/api/auth/email/register", json={
        "email": email,
        "password": "old-password-123",
    })
    assert resp.json()["code"] == 0, resp.text
    return email


async def test_duplicate_order_request_reuses_same_pending_order(client):
    await _register(client)
    payload = {
        "sku_code": "demo_echo",
        "channel": "wechat",
        "biz_data": {"text": "same request"},
    }
    first = (await client.post("/api/order/create", json=payload)).json()
    second = (await client.post("/api/order/create", json=payload)).json()
    assert first["code"] == second["code"] == 0
    assert first["data"]["order_no"] == second["data"]["order_no"]


async def test_active_intent_unique_constraint_blocks_two_pending_orders(db):
    user = User(email="active-intent@example.com", password_hash="x")
    db.add(user)
    await db.flush()
    db.add(Product(
        sku_code="intent_sku", product_type="single", feature="intent",
        name="Intent", price="1.00", enabled=1,
    ))
    db.add(Order(
        order_no="INTENT-1", user_id=user.id, sku_code="intent_sku",
        product_name="Intent", amount=Decimal("1.00"),
        status="pending", active_key="active",
    ))
    await db.flush()
    with pytest.raises(IntegrityError):
        async with db.begin_nested():
            db.add(Order(
                order_no="INTENT-2", user_id=user.id, sku_code="intent_sku",
                product_name="Intent", amount=Decimal("1.00"),
                status="pending", active_key="active",
            ))
            await db.flush()


async def test_password_reset_consumes_one_time_code(client):
    email = await _register(client)
    requested = (await client.post(
        "/api/auth/password/reset-request", json={"email": email}
    )).json()
    assert requested["code"] == 0
    code = requested["data"].get("dev_code")
    assert code and len(code) == 6

    confirmed = (await client.post("/api/auth/password/reset-confirm", json={
        "email": email,
        "code": code,
        "new_password": "new-password-456",
    })).json()
    assert confirmed["code"] == 0, confirmed
    old_session = await client.get("/api/user/info")
    assert old_session.status_code == 401

    old_login = (await client.post("/api/auth/email/login", json={
        "email": email, "password": "old-password-123",
    })).json()
    new_login = (await client.post("/api/auth/email/login", json={
        "email": email, "password": "new-password-456",
    })).json()
    assert old_login["code"] != 0
    assert new_login["code"] == 0

    replay = (await client.post("/api/auth/password/reset-confirm", json={
        "email": email,
        "code": code,
        "new_password": "another-password-789",
    })).json()
    assert replay["code"] != 0


async def test_sensitive_header_is_allowed_by_cors_preflight(client):
    resp = await client.options("/api/admin/card/generate", headers={
        "Origin": "https://frontend.example",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "x-operate-password,x-admin-token",
    })
    assert resp.status_code == 200
    assert "x-operate-password" in resp.headers.get(
        "access-control-allow-headers", "").lower()


async def test_quota_lock_honours_fail_closed(monkeypatch):
    class BrokenRedis:
        async def set(self, *_args, **_kwargs):
            raise ConnectionError("redis down")

    monkeypatch.setattr(settings, "REDIS_FAIL_CLOSED", True, raising=False)
    token = await redis_acquire_lock(
        BrokenRedis(), "lock:quota", 60, fail_closed=True)
    assert token == ""


def test_deployment_templates_do_not_reintroduce_audit_findings():
    init_sql = (ROOT / "sql" / "init.sql").read_text(encoding="utf-8")
    dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8")
    nginx = (ROOT / "nginx" / "nginx.conf").read_text(encoding="utf-8")
    assert "CREATE DATABASE" not in init_sql.upper()
    assert "USE `app_db`" not in init_sql
    assert ".venv/" in dockerignore
    assert "EDGE_PROXY_AUTH_SECRET" in nginx
    assert "limit_req_zone $binary_remote_addr" not in nginx


async def test_auto_refund_persists_refund_number_before_channel_call(
        tmp_path, monkeypatch):
    engine = create_async_engine(
        f"sqlite+aiosqlite:///{(tmp_path / 'refund.db').as_posix()}")
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with factory() as db:
        db.add(Order(
            order_no="AUTO-REFUND-1", user_id=1, sku_code="demo_echo",
            product_type="report", product_name="Report",
            amount=Decimal("9.90"), status="completed",
            pay_channel="wechat", paid_at=datetime.now(),
            fulfilled_at=datetime.now(),
        ))
        await db.flush()
        order_id = (await db.execute(select(Order.id).where(
            Order.order_no == "AUTO-REFUND-1"))).scalar_one()
        db.add(Report(
            order_id=order_id, user_id=1, status="failed",
            retry_count=0, updated_at=datetime.now() - timedelta(minutes=11),
        ))
        await db.commit()

    observed = []

    async def fake_apply_refund(*, refund_no, **_kwargs):
        async with factory() as checker:
            persisted = (await checker.execute(select(Refund).where(
                Refund.refund_no == refund_no))).scalar_one_or_none()
            observed.append(persisted is not None)
        return RefundResult("success", refund_no)

    async def fake_revoke(_db, _order):
        return ""

    async def fake_lock(*_args, **_kwargs):
        return True

    monkeypatch.setattr(scheduler, "AsyncSessionLocal", factory)
    monkeypatch.setattr(scheduler, "apply_refund", fake_apply_refund)
    monkeypatch.setattr(scheduler, "revoke_refunded_order", fake_revoke)
    monkeypatch.setattr(scheduler, "_acquire_lock", fake_lock)

    await scheduler.auto_refund_failed_reports()
    assert observed == [True]
    async with factory() as db:
        refund = (await db.execute(select(Refund).where(
            Refund.order_id == order_id))).scalar_one()
        assert refund.status == "refunded"
    await engine.dispose()
