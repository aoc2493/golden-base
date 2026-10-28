"""生产环境红线：模拟支付、示例密钥必须被启动自检拒绝。"""
import pytest

from app.config import settings
from app.main import _SAMPLE_SECRET_VALUES, _startup_check


def _prod_ready(monkeypatch):
    """把除被测项以外的生产阻断项全部配齐，确保失败原因只能是目标项。"""
    monkeypatch.setattr(settings, "APP_ENV", "production", raising=False)
    monkeypatch.setattr(settings, "CORS_ORIGINS", "https://example.com", raising=False)
    monkeypatch.setattr(settings, "ADMIN_OPERATE_PASSWORD", "strong-operate-password", raising=False)
    monkeypatch.setattr(settings, "AI_MARK_PROVIDER_NAME", "Example Provider", raising=False)
    monkeypatch.setattr(settings, "DB_TYPE", "sqlite", raising=False)


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


def test_example_secrets_allowed_outside_production(monkeypatch):
    """README 的 cp .env.example .env 本地流程必须能直接启动。"""
    monkeypatch.setattr(settings, "APP_ENV", "development", raising=False)
    monkeypatch.setattr(settings, "SENSITIVE_FIELD_KEY", _SAMPLE_SECRET_VALUES["SENSITIVE_FIELD_KEY"],
                        raising=False)
    monkeypatch.setattr(settings, "JWT_SECRET_KEY", _SAMPLE_SECRET_VALUES["JWT_SECRET_KEY"], raising=False)
    monkeypatch.setattr(settings, "ADMIN_TOKEN", _SAMPLE_SECRET_VALUES["ADMIN_TOKEN"], raising=False)

    _startup_check()  # 不抛异常即通过
