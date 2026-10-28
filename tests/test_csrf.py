"""CSRF 判据：Cookie 会话的状态变更请求必须带同源 Origin；Bearer 与支付回调不在此列。"""
import uuid

from app.core.auth import AUTH_COOKIE_NAME


async def _register(client) -> None:
    email = f"csrf-{uuid.uuid4().hex[:8]}@example.com"
    resp = await client.post("/api/auth/email/register",
                             json={"email": email, "password": "password123"})
    assert resp.json()["code"] == 0, resp.text


async def test_cookie_post_from_other_site_is_rejected(client):
    await _register(client)
    assert client.cookies.get(AUTH_COOKIE_NAME)

    resp = await client.post("/api/demo/echo", json={"text": "x"},
                             headers={"Origin": "https://evil.example"})
    assert resp.status_code == 403
    assert resp.json()["code"] == 6002  # ErrorCode.CSRF_FAILED


async def test_cookie_post_without_usable_origin_is_rejected(client):
    """Origin: null（沙箱 iframe）解析不出 host，按跨站处理。"""
    await _register(client)

    resp = await client.post("/api/order/create",
                             json={"sku_code": "demo_echo", "channel": "wechat",
                                   "biz_data": {"text": "x"}},
                             headers={"Origin": "null"})
    assert resp.status_code == 403


async def test_bearer_token_bypasses_origin_check(client):
    """Bearer 令牌不会被浏览器自动附带，不构成 CSRF 面，因此不需要 Origin。"""
    await _register(client)
    token = client.cookies.get(AUTH_COOKIE_NAME)
    assert token

    resp = await client.post("/api/demo/echo", json={"text": "x"},
                             headers={"Origin": "https://evil.example",
                                      "Authorization": f"Bearer {token}"})
    # 到达业务层（未购买 → 权限不足），而不是被中间件拦下
    assert resp.status_code == 200
    assert resp.json()["code"] == 1003


async def test_payment_callback_paths_are_not_origin_checked(client):
    """支付平台回调是服务端到服务端，无 Origin，安全性由验签保证。"""
    resp = await client.post("/api/payment/wechat/notify", content=b"{}",
                             headers={"Origin": "null"})
    assert resp.status_code != 403
