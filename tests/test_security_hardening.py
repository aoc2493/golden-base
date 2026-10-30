"""安全边界回归：以下断言失效会重新打开对应攻击面。

覆盖：
  · X-Request-ID 反射注入/日志投毒（只接受受限字符集，其余一律重新生成）
  · 头像/反馈图地址白名单（伪协议、外站、反斜线变形）
  · CSRF 的 Origin 判定（协议必须与白名单一致，不同 scheme 不算同源）
  · 权益校验 sides 的 4KB 上限（丢失则可用超大 JSON 打满带宽/内存）
  · 管理端无令牌必须 HTTP 401 + code=6001（不能是 200）
  · 推广触达上报端点可匿名调用但非法邀请码不落库
"""
import re

import pytest
from pydantic import ValidationError

from app.config import settings
from app.core.schemas import EntitlementCheckRequest, FeedbackRequest, UserUpdateRequest
from app.main import CSRFMiddleware


# ---------------- X-Request-ID ----------------
async def test_request_id_is_sanitized(client):
    raw = "bad id <script>"
    resp = await client.get("/health", headers={"X-Request-ID": raw})
    rid = resp.headers.get("X-Request-ID", "")
    assert rid and rid != raw
    assert re.fullmatch(r"[A-Za-z0-9._-]{1,64}", rid), rid


async def test_valid_request_id_is_reused(client):
    resp = await client.get("/health", headers={"X-Request-ID": "edge-01.abc_DEF"})
    assert resp.headers.get("X-Request-ID") == "edge-01.abc_DEF"


# ---------------- 图片地址白名单 ----------------
@pytest.fixture
def cos_conf(monkeypatch):
    monkeypatch.setattr(settings, "COS_CDN_DOMAIN", "https://cdn.example.com")
    monkeypatch.setattr(settings, "COS_BUCKET", "demo-bucket")
    monkeypatch.setattr(settings, "COS_REGION", "ap-guangzhou")


def test_avatar_accepts_site_relative_and_cos_urls(cos_conf):
    assert UserUpdateRequest(avatar_url="/avatars/a.png").avatar_url == "/avatars/a.png"
    for url in ("https://cdn.example.com/a.png",
                "https://demo-bucket.cos.ap-guangzhou.myqcloud.com/a.png"):
        assert UserUpdateRequest(avatar_url=url).avatar_url == url
    assert UserUpdateRequest(avatar_url="").avatar_url is None


@pytest.mark.parametrize("bad", [
    "javascript:alert(1)",
    "data:text/html;base64,PHNjcmlwdD4=",
    "//evil.example.com/a.png",
    "/\\evil.example.com/a.png",
    "/../etc/passwd",
    "https://evil.example.com/a.png",
    "https://cdn.example.com.evil.com/a.png",
])
def test_avatar_rejects_unsafe_urls(cos_conf, bad):
    with pytest.raises(ValidationError):
        UserUpdateRequest(avatar_url=bad)


def test_feedback_images_share_the_same_whitelist(cos_conf):
    fb = FeedbackRequest(type="其他", content="x",
                         images=["https://cdn.example.com/a.png"])
    assert fb.images == ["https://cdn.example.com/a.png"]
    with pytest.raises(ValidationError):
        FeedbackRequest(type="其他", content="x", images=["https://evil.example.com/a.png"])


# ---------------- CSRF Origin ----------------
def test_origin_requires_matching_scheme(monkeypatch):
    monkeypatch.setattr(settings, "CORS_ORIGINS", "https://app.example.com")
    ok = CSRFMiddleware._origin_ok({b"origin": b"https://app.example.com"})
    wrong_scheme = CSRFMiddleware._origin_ok({b"origin": b"http://app.example.com"})
    sandbox = CSRFMiddleware._origin_ok({b"origin": b"null"})
    foreign = CSRFMiddleware._origin_ok({b"origin": b"https://evil.example.com"})
    assert ok is True
    assert wrong_scheme is False
    assert sandbox is False
    assert foreign is False


def test_origin_same_host_allowed_regardless_of_scheme(monkeypatch):
    # 反代终止 TLS 时 Origin 是 https、Host 不带 scheme，同站判定只比 host:port
    monkeypatch.setattr(settings, "CORS_ORIGINS", "")
    assert CSRFMiddleware._origin_ok(
        {b"origin": b"https://shop.example.com", b"host": b"shop.example.com"}) is True


# ---------------- 权益入参上限 ----------------
def test_entitlement_sides_over_4kb_rejected():
    with pytest.raises(ValidationError):
        EntitlementCheckRequest(feature="demo", sides=[{"note": "x" * 5000}])


def test_entitlement_feature_accepts_plugin_namespace():
    """插件能力码带点（manifest 里 code="demo.echo"），白名单正则不能把它排掉；
    同时仍要拦住大写/空段/超长（feature 列是 VARCHAR(20)）。"""
    assert EntitlementCheckRequest(feature="demo.echo").feature == "demo.echo"
    assert EntitlementCheckRequest(feature="vip").feature == "vip"
    for bad in ("demo..echo", ".demo", "Demo.echo", "demo echo", "x" * 21):
        with pytest.raises(ValidationError):
            EntitlementCheckRequest(feature=bad)


# ---------------- 管理端鉴权 ----------------
async def test_admin_endpoint_without_token_is_401(client):
    resp = await client.get("/api/admin/dashboard")
    assert resp.status_code == 401
    body = resp.json()
    assert body["code"] == 6001


# ---------------- 推广触达 ----------------
async def test_distribution_touch_unknown_code_records_nothing(client):
    resp = await client.post("/api/distribution/touch",
                             json={"invite_code": "NOSUCHCODE", "visitor_key": "vk-1"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["code"] == 0
    assert body["data"]["recorded"] is False
