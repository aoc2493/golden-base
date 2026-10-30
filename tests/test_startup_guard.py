"""生产环境红线：模拟支付、示例密钥、Redis 可达性、未确认的法定义务缺口必须被启动自检拒绝。"""
import logging

import pytest

from app.config import settings
from app.main import (
    _SAMPLE_SECRET_VALUES,
    _check_redis_reachable,
    _startup_check,
)


def _prod_ready(monkeypatch):
    """把除被测项以外的生产阻断项全部配齐，确保失败原因只能是目标项。"""
    monkeypatch.setattr(settings, "APP_ENV", "production", raising=False)
    monkeypatch.setattr(settings, "CORS_ORIGINS", "https://example.com", raising=False)
    monkeypatch.setattr(settings, "ADMIN_OPERATE_PASSWORD", "strong-operate-password", raising=False)
    monkeypatch.setattr(settings, "AI_MARK_PROVIDER_NAME", "Example Provider", raising=False)
    monkeypatch.setattr(settings, "DB_TYPE", "sqlite", raising=False)
    monkeypatch.setattr(settings, "REQUIRE_EMAIL_VERIFICATION", True, raising=False)
    monkeypatch.setattr(settings, "EMAIL_SMTP_HOST", "smtp.example.com", raising=False)
    monkeypatch.setattr(settings, "EMAIL_SMTP_FROM", "noreply@example.com", raising=False)
    # 合规缺口确认位默认 False（未确认即拒启动），这里默认打开，
    # 免得每个用例都因它失败而看不见自己要测的那一项——它本身另有专门用例覆盖。
    monkeypatch.setattr(settings, "COMPLIANCE_DECISIONS_ACK", True, raising=False)


def test_mock_payment_blocked_in_production(monkeypatch):
    _prod_ready(monkeypatch)
    monkeypatch.setattr(settings, "PAYMENT_MOCK", True, raising=False)

    with pytest.raises(RuntimeError, match="PAYMENT_MOCK"):
        _startup_check()


def test_example_secrets_blocked_in_production(monkeypatch):
    """.env.example 的 dev 密钥长度过得了强度门槛，生产必须按值拦下。"""
    _prod_ready(monkeypatch)
    monkeypatch.setattr(settings, "PAYMENT_MOCK", False, raising=False)
    monkeypatch.setattr(settings, "SENSITIVE_FIELD_KEY", _SAMPLE_SECRET_VALUES["SENSITIVE_FIELD_KEY"],
                        raising=False)

    with pytest.raises(RuntimeError, match="SENSITIVE_FIELD_KEY 仍是 .env.example 的示例值"):
        _startup_check()


def test_missing_email_transport_blocks_production_when_verification_required(monkeypatch):
    _prod_ready(monkeypatch)
    monkeypatch.setattr(settings, "PAYMENT_MOCK", False, raising=False)
    monkeypatch.setattr(settings, "EMAIL_SMTP_HOST", "", raising=False)
    with pytest.raises(RuntimeError, match="SMTP 未配置"):
        _startup_check()


def test_trusted_proxy_requires_shared_secrets_in_production(monkeypatch):
    _prod_ready(monkeypatch)
    monkeypatch.setattr(settings, "PAYMENT_MOCK", False, raising=False)
    monkeypatch.setattr(settings, "TRUST_PROXY_HEADERS", True, raising=False)
    monkeypatch.setattr(settings, "PROXY_AUTH_SECRET", "", raising=False)
    monkeypatch.setattr(settings, "EDGE_PROXY_AUTH_SECRET", "", raising=False)
    with pytest.raises(RuntimeError, match="PROXY_AUTH_SECRET|EDGE_PROXY_AUTH_SECRET"):
        _startup_check()


def test_example_secrets_allowed_outside_production(monkeypatch):
    """README 的 cp .env.example .env 本地流程必须能直接启动。"""
    monkeypatch.setattr(settings, "APP_ENV", "development", raising=False)
    monkeypatch.setattr(settings, "SENSITIVE_FIELD_KEY", _SAMPLE_SECRET_VALUES["SENSITIVE_FIELD_KEY"],
                        raising=False)
    monkeypatch.setattr(settings, "JWT_SECRET_KEY", _SAMPLE_SECRET_VALUES["JWT_SECRET_KEY"], raising=False)
    monkeypatch.setattr(settings, "ADMIN_TOKEN", _SAMPLE_SECRET_VALUES["ADMIN_TOKEN"], raising=False)

    _startup_check()  # 不抛异常即通过


class _DownRedis:
    """redis.from_url 的写照：构造成功，第一个命令才炸。"""

    async def ping(self):
        raise ConnectionError("Error 111 connecting to redis:6379")


class _UpRedis:
    async def ping(self):
        return True


async def test_redis_unreachable_blocks_production(monkeypatch):
    """生产启动必须 PING 通 Redis：from_url 惰性建连，地址/密码写错时服务照样「启动成功」，
    而限流、token 黑名单、会员额度互斥锁要等到真实请求才被发现有全量失效。"""
    monkeypatch.setattr(settings, "APP_ENV", "production", raising=False)
    with pytest.raises(RuntimeError, match="Redis 连不上"):
        await _check_redis_reachable(client=_DownRedis())


async def test_redis_client_not_initialised_blocks_production(monkeypatch):
    monkeypatch.setattr(settings, "APP_ENV", "production", raising=False)
    monkeypatch.setattr("app.core.auth.redis_client", None, raising=False)
    with pytest.raises(RuntimeError, match="Redis 客户端未初始化"):
        await _check_redis_reachable()


async def test_reachable_redis_passes_production(monkeypatch):
    """反向保证：这条门禁不是一律拒绝。Redis 正常时生产必须照常启动。"""
    monkeypatch.setattr(settings, "APP_ENV", "production", raising=False)
    await _check_redis_reachable(client=_UpRedis())


async def test_redis_check_skipped_outside_production(monkeypatch):
    """README 的「本地开发（无 Docker）」链路刻意不带 Redis，不能被这条门禁拦死。"""
    monkeypatch.setattr(settings, "APP_ENV", "development", raising=False)
    await _check_redis_reachable(client=_DownRedis())


def test_fail_open_redis_is_loud_in_production(monkeypatch, caplog):
    """REDIS_FAIL_CLOSED=false 运营方的可用性取舍，不阻断启动，但每次启动都要以 ERROR 留痕。"""
    _prod_ready(monkeypatch)
    monkeypatch.setattr(settings, "PAYMENT_MOCK", False, raising=False)
    monkeypatch.setattr(settings, "REDIS_FAIL_CLOSED", False, raising=False)
    _startup_check()  # 不阻断（运营方取舍），只要求留痕
    assert "REDIS_FAIL_CLOSED" in caplog.text


# ---------------- 法定义务缺口的确认闸门（COMPLIANCE_DECISIONS_ACK） ----------------

def _prod_no_ack(monkeypatch):
    _prod_ready(monkeypatch)
    monkeypatch.setattr(settings, "PAYMENT_MOCK", False, raising=False)
    monkeypatch.setattr(settings, "COMPLIANCE_DECISIONS_ACK", False, raising=False)


def test_unconfirmed_compliance_gaps_block_production(monkeypatch):
    """三项都没确认处置时生产起不来：把「有人决定过」变成上线的硬前置。

    这条门禁不是把默认值改成打开——那会推翻项目已记录的决策、并让没接 UI 的部署全员下不了单；
    它要求的是显式确认，确认前后差异只有一行 .env，但静默裸奔的路径被彻底堵死。
    """
    _prod_no_ack(monkeypatch)
    with pytest.raises(RuntimeError) as exc:
        _startup_check()
    msg = str(exc.value)
    for item in ("ENFORCE_PAYMENT_DISCLAIMER", "WITHDRAW_TAX_ENABLED", "年龄门槛"):
        assert item in msg, f"{item} 未进入阻断项：{msg}"
    assert "COMPLIANCE_DECISIONS_ACK" in msg


def test_acked_compliance_gaps_boot_but_stay_loud(monkeypatch, caplog):
    """确认后放行启动，但仍逐条以 ERROR 留痕：确认不等于闭嘴。"""
    _prod_ready(monkeypatch)
    monkeypatch.setattr(settings, "PAYMENT_MOCK", False, raising=False)
    with caplog.at_level(logging.WARNING):
        _startup_check()
    loud = [r for r in caplog.records if any(k in r.getMessage() for k in
            ("ENFORCE_PAYMENT_DISCLAIMER", "WITHDRAW_TAX_ENABLED", "年龄门槛"))]
    assert len(loud) == 3, [r.getMessage() for r in loud]
    assert all(r.levelname == "ERROR" for r in loud), [(r.levelname, r.getMessage()) for r in loud]


def test_opened_switches_shrink_the_gap_list(monkeypatch, caplog):
    """打开一项，阻断项就少一条：闸门数的是真实缺口，不是一律拒绝。"""
    _prod_no_ack(monkeypatch)
    monkeypatch.setattr(settings, "ENFORCE_PAYMENT_DISCLAIMER", True, raising=False)
    monkeypatch.setattr(settings, "WITHDRAW_TAX_ENABLED", True, raising=False)
    with pytest.raises(RuntimeError) as exc:
        _startup_check()
    msg = str(exc.value)
    assert "年龄门槛" in msg
    assert "ENFORCE_PAYMENT_DISCLAIMER" not in msg and "WITHDRAW_TAX_ENABLED" not in msg


def test_compliance_gate_does_not_reach_local_runs(monkeypatch):
    """本地/演示链路（cp .env.example .env 即起）不受这道闸门约束。"""
    monkeypatch.setattr(settings, "APP_ENV", "development", raising=False)
    monkeypatch.setattr(settings, "COMPLIANCE_DECISIONS_ACK", False, raising=False)
    _startup_check()  # 不抛异常即通过
