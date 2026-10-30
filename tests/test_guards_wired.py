"""接线控制点：接口文档承诺的校验必须由实际代码执行。

测试把文档、路由与服务实现绑定在一起；删除对应校验或接错取值时，用例必须失败。
"""
from datetime import datetime
from decimal import Decimal

import pytest
from sqlalchemy import select

from app.core.api.favorite import FavoriteAddRequest, favorite_add
from app.core.api.payment import _handle_wechat_refund
from app.core.models import Favorite, Order, Report, Refund, User

DEVICE_CODE = "h5-" + "a1b2c3d4e5f6g7h8i9j0k1l2"  # 与 _DEVICE_CODE_RE 同格式（≥20 位字母数字）


async def test_released_device_code_cannot_log_in(client, monkeypatch):
    """已解绑的设备码登录必须被明确拒绝，且不得静默发出新会话。

    /device/release 的接口契约是凭证失效后再次登录必须收到明确提示，不能静默
    新建空账号。解绑会置空 users.device_code，因此登录链路必须先查询已释放标记。
    """
    from app.core.api import auth as auth_api

    marked = []

    async def fake_released(code):
        marked.append(code)
        return True

    monkeypatch.setattr(auth_api, "is_device_code_released", fake_released)
    r = await client.post("/api/auth/login", json={"code": DEVICE_CODE})
    body = r.json()
    assert marked == [DEVICE_CODE], "登录链路没有查询「设备码是否已解绑」"
    assert body.get("code") == 1002, f"已解绑设备码未被拒绝: {body}"
    assert "set-cookie" not in r.headers, "已解绑的设备码仍然换到了会话"


async def test_login_honours_rate_limiter_verdict(client, monkeypatch):
    """限流器判定超限时，设备码登录必须直接拒绝且不发会话。

    测试注入限流判定，验证登录链路把判定结果当作放行条件，且被拒的请求不会建号、
    不会签发 Cookie。Lua 滑动窗口本身需要真实 Redis 环境验证。
    """
    from app.core.api import auth as auth_api

    keys = []

    async def fake_limit(rc, key, limit, window):
        keys.append((key, limit, window))
        # 只对 login_limit 给出「第 2 次起超限」的判定；其余键（建号前的 register_limit 等）照常放行
        if key.startswith("login_limit:"):
            return sum(1 for k, *_ in keys if k.startswith("login_limit:")) == 1
        return True

    monkeypatch.setattr(auth_api, "redis_rate_limit", fake_limit)
    first = await client.post("/api/auth/login", json={"code": DEVICE_CODE})
    second = await client.post("/api/auth/login", json={"code": DEVICE_CODE})
    assert first.json().get("code") == 0, f"首次登录被误拒: {first.json()}"
    body = second.json()
    assert body.get("code") == 1004, f"限流判定未被执行: {body}"
    assert "set-cookie" not in second.headers, "被限流的登录请求仍然签发了会话 Cookie"
    login_calls = [lw for lw in keys if lw[0].startswith("login_limit:")]
    assert len(login_calls) == 2, f"登录限流判定次数不符: {login_calls}"
    assert auth_api._LOGIN_LIMIT in [c[1] for c in login_calls], "限流阈值未取自 _LOGIN_LIMIT"


async def test_favorite_is_unique_per_user_item(db):
    """同一用户对同一条目只能有一行收藏（并发双击的第二笔必须撞约束）。

    缺这条约束时，重复收藏会让 api/favorite.py 的查重（scalar_one_or_none）读到两行
    并抛 MultipleResultsFound，该条目此后每次收藏都 500。
    """
    from sqlalchemy.exc import IntegrityError

    db.add(Favorite(user_id=1, item_type="report", item_id=10, title="a"))
    await db.flush()
    db.add(Favorite(user_id=1, item_type="report", item_id=10, title="b"))
    with pytest.raises(IntegrityError):
        await db.flush()
    await db.rollback()

    # 不同条目 / 不同用户可以并存
    db.add(Favorite(user_id=1, item_type="report", item_id=11, title="c"))
    db.add(Favorite(user_id=2, item_type="report", item_id=10, title="d"))
    await db.flush()


async def test_favorite_add_twice_returns_same_row(db):
    """重复收藏走幂等返回，不产生第二行。"""
    user = User(nickname="收藏者")
    db.add(user)
    await db.flush()
    order = Order(order_no="FAV-1", user_id=user.id, product_name="报告",
                  amount=Decimal("39.90"), status="completed", paid_at=datetime.now())
    db.add(order)
    await db.flush()
    db.add(Report(order_id=order.id, user_id=user.id, status="done"))
    await db.flush()

    req = FavoriteAddRequest(item_type="report", item_id=order.id)
    first = await favorite_add(req, db=db, user=user)
    second = await favorite_add(req, db=db, user=user)
    assert first["data"]["id"] == second["data"]["id"], f"两次收藏返回不同行: {first} {second}"
    rows = (await db.execute(select(Favorite).where(
        Favorite.user_id == user.id))).scalars().all()
    assert len(rows) == 1


async def _make_refund(db, amount="39.90", status="processing"):
    user = User(nickname="退款者")
    db.add(user)
    await db.flush()
    order = Order(order_no="RF-1", user_id=user.id, product_name="报告",
                  amount=Decimal(amount), status="refund_pending",
                  paid_at=datetime.now(), fulfilled_at=datetime.now())
    db.add(order)
    await db.flush()
    refund = Refund(order_id=order.id, user_id=user.id, refund_no="RFNO-1",
                    reason="用户申请", status=status)
    db.add(refund)
    await db.flush()
    return order, refund


async def test_wechat_refund_callback_amount_mismatch_is_rejected(db):
    """退款回调金额与订单金额不符必须拒绝迁移（本底盘退款一律全额）。

    退款回调分支不写 result["amount"]，因此校验必须使用 refund_amount 与 refund.amount
    （Refund 表没有这一列），两个都是 None → 校验永远不进分支，等于没有。
    """
    order, refund = await _make_refund(db)
    ok = await _handle_wechat_refund(db, {
        "refund_no": refund.refund_no, "refund_status": "SUCCESS",
        "refund_amount": Decimal("9.90")})
    assert ok is False, "金额被篡改/部分退款仍被接受"
    await db.refresh(refund)
    assert refund.status == "processing", "拒绝迁移却仍改了退款单状态"


async def test_wechat_refund_callback_without_amount_is_rejected(db):
    """回调不带退款金额＝报文畸形，按可疑处理：拒绝迁移，等渠道重试或后台主动查单。"""
    order, refund = await _make_refund(db)
    ok = await _handle_wechat_refund(db, {
        "refund_no": refund.refund_no, "refund_status": "SUCCESS"})
    assert ok is False
    await db.refresh(refund)
    assert refund.status == "processing"


async def test_wechat_refund_callback_full_amount_is_applied(db):
    """金额一致时正常迁移（证明上一条不是「一律拒绝」把链路焊死）。"""
    order, refund = await _make_refund(db, amount="39.90")
    ok = await _handle_wechat_refund(db, {
        "refund_no": refund.refund_no, "refund_status": "SUCCESS",
        "refund_amount": Decimal("39.90")})
    assert ok is True
    await db.refresh(refund)
    assert refund.status == "refunded"
    await db.refresh(order)
    assert order.status == "refunded"
