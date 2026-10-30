"""SMTP delivery for account verification and password reset messages.

The project must not report that a verification message was sent when no
transport is configured.  Delivery is intentionally synchronous inside
``asyncio.to_thread`` because Python's standard-library SMTP client blocks.
"""
from __future__ import annotations

import asyncio
import smtplib
from email.message import EmailMessage

from app.config import settings


def is_configured() -> bool:
    """Return whether a usable SMTP relay is configured."""
    return bool(settings.EMAIL_SMTP_HOST and
                (settings.EMAIL_SMTP_FROM or settings.EMAIL_SMTP_USER))


def _send_sync(to_email: str, subject: str, body: str) -> None:
    if not is_configured():
        raise RuntimeError("SMTP is not configured")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = settings.EMAIL_SMTP_FROM or settings.EMAIL_SMTP_USER
    msg["To"] = to_email
    msg.set_content(body)

    host = settings.EMAIL_SMTP_HOST
    port = int(settings.EMAIL_SMTP_PORT)
    # Port 465 is implicit TLS. Other ports use STARTTLS when enabled.
    client: smtplib.SMTP | smtplib.SMTP_SSL
    if port == 465:
        client = smtplib.SMTP_SSL(host, port, timeout=15)
    else:
        client = smtplib.SMTP(host, port, timeout=15)
    try:
        if port != 465 and settings.EMAIL_SMTP_TLS:
            client.starttls()
        if settings.EMAIL_SMTP_USER:
            client.login(settings.EMAIL_SMTP_USER, settings.EMAIL_SMTP_PASSWORD)
        client.send_message(msg)
    finally:
        try:
            client.quit()
        except Exception:
            client.close()


async def _send(to_email: str, subject: str, body: str) -> None:
    await asyncio.to_thread(_send_sync, to_email, subject, body)


async def send_verification_code(email: str, code: str) -> None:
    await _send(
        email,
        "Golden Base 注册验证码",
        f"你的注册验证码是：{code}\n\n"
        f"验证码 {settings.EMAIL_VERIFICATION_TTL_SECONDS // 60} 分钟内有效。"
        "如非本人操作，请忽略本邮件。",
    )


async def send_password_reset_code(email: str, code: str) -> None:
    await _send(
        email,
        "Golden Base 密码重置验证码",
        f"你的密码重置验证码是：{code}\n\n"
        f"验证码 {settings.PASSWORD_RESET_TTL_SECONDS // 60} 分钟内有效。"
        "如非本人操作，请忽略本邮件。",
    )
