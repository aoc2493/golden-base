"""端到端链路：注册 → 商品 → 下单 → 模拟支付 → 权益校验 → 业务接口。

库与客户端来自 conftest：默认内存 SQLite，`DB_TYPE=mysql` 时打真实 MySQL。
"""
import uuid


async def _post(client, path, payload):
    resp = await client.post(path, json=payload)
    return resp.json()


async def _get_products(client):
    resp = await client.get("/api/product/list")
    return resp.json()


async def test_demo_purchase_unlocks_capability(client):
    email = f"demo-{uuid.uuid4().hex[:8]}@example.com"
    reg = await _post(client, "/api/auth/email/register",
                      {"email": email, "password": "password123"})
    assert reg["code"] == 0, reg

    products = await _get_products(client)
    assert products["code"] == 0, products
    skus = [p["sku_code"] for p in products["data"]["list"]]
    assert "demo_echo" in skus

    text = "hello, golden base"
    locked = await _post(client, "/api/demo/echo", {"text": text})
    assert locked["code"] == 1003, locked

    order = await _post(client, "/api/order/create", {
        "sku_code": "demo_echo",
        "channel": "wechat",
        "biz_data": {"text": text},
    })
    assert order["code"] == 0, order
    assert order["data"]["pay_params"]["pay_type"] == "mock"
    assert order["data"]["amount"] == 1.0

    paid = await _post(client, "/api/payment/mock/pay", {"order_no": order["data"]["order_no"]})
    assert paid["code"] == 0, paid
    assert paid["data"]["status"] == "completed"

    checked = await _post(client, "/api/entitlement/check",
                          {"feature": "demo.echo", "sides": [text]})
    assert checked["code"] == 0, checked
    assert checked["data"]["allowed"] is True

    echoed = await _post(client, "/api/demo/echo", {"text": text})
    assert echoed["code"] == 0, echoed
    assert echoed["data"]["text"] == text


async def test_mock_pay_rejects_unpaid_other_user(client):
    """未支付订单不能被别人的账号用模拟支付接口履约。"""
    first = f"user-a-{uuid.uuid4().hex[:8]}@example.com"
    second = f"user-b-{uuid.uuid4().hex[:8]}@example.com"
    assert (await _post(client, "/api/auth/email/register",
                        {"email": first, "password": "password123"}))["code"] == 0
    order = await _post(client, "/api/order/create", {
        "sku_code": "demo_echo", "channel": "wechat", "biz_data": {"text": "a"},
    })
    assert order["code"] == 0, order

    await client.post("/api/auth/logout")
    assert (await _post(client, "/api/auth/email/register",
                        {"email": second, "password": "password123"}))["code"] == 0
    hijack = await _post(client, "/api/payment/mock/pay",
                         {"order_no": order["data"]["order_no"]})
    assert hijack["code"] != 0
