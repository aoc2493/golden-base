# -*- coding: utf-8 -*-
"""日志脱敏工具：防止敏感信息泄露到日志。

使用场景：
  · 所有 logger.info/error 调用前，敏感字段必须脱敏
  · 手机号、邮箱、身份证、银行卡、密码、密钥、Token 等

脱敏规则：
  · 手机号：138****0000
  · 邮箱：t***@163.com
  · 身份证：110101********1234
  · 银行卡：622202******1234
  · 密码/密钥/Token：******
"""
from __future__ import annotations

import re
from typing import Any

# 正则模式
_PHONE_RE = re.compile(r"(1[3-9])(\d{4})(\d{4})")
_EMAIL_RE = re.compile(r"([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})")
_IDCARD_RE = re.compile(r"(\d{6})\d{8}(\d{4})")
_BANKCARD_RE = re.compile(r"(\d{6})\d+(\d{4})")

# 敏感字段名（用于 sanitize_dict 按「字段名」判断，不含值的匹配）
_SENSITIVE_KEY_NAMES = re.compile(
    r"(password|passwd|secret|token|key|signature|signature_value|cookie|session|authorization|pwd|app_secret|appsecret)",
    re.IGNORECASE,
)

# 敏感字段名 + 值（key=value / key: value 形式）
# 原正则只匹配关键词本身、不捕获等号后的值：
# 对 "password=hunter2" 匹配到的只有 "password"，替换结果是
# "password=******=hunter2"——真实口令原样保留，脱敏形同虚设。
# 把「关键词 + 分隔符 + 值」整体捕获替换，避免值外泄。
_SENSITIVE_KEY_VALUES = re.compile(
    r"(password|passwd|secret|token|key|signature|signature_value|cookie|session|authorization|pwd|app_secret|appsecret)"
    r"(\s*[=:]\s*)([^\s,;&'\"]+)",
    re.IGNORECASE,
)

# Bearer 令牌与 JWT 形态（无 key= 前缀时兜底）
_BEARER_RE = re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]+")
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{4,}")


def mask_phone(text: str) -> str:
    """手机号脱敏：138****0000"""
    return _PHONE_RE.sub(r"\1****\3", text)


def mask_email(text: str) -> str:
    """邮箱脱敏：t***@163.com"""
    def _mask(m):
        name = m.group(1)
        masked = name[0] + "*" * (len(name) - 1) if len(name) > 1 else name[0]
        return f"{masked}@{m.group(2)}"
    return _EMAIL_RE.sub(_mask, text)


def mask_idcard(text: str) -> str:
    """身份证脱敏：110101********1234"""
    return _IDCARD_RE.sub(r"\1********\2", text)


def mask_bankcard(text: str) -> str:
    """银行卡脱敏：622202******1234"""
    return _BANKCARD_RE.sub(r"\1******\2", text)


def mask_sensitive_key_value(text: str) -> str:
    """对 key=value / key: value 形式的敏感字段整体脱敏：password=xxx → password=******"""
    def _mask(m):
        return f"{m.group(1)}=******"
    return _SENSITIVE_KEY_VALUES.sub(_mask, text)


def mask_bearer_tokens(text: str) -> str:
    """遮盖 Bearer 令牌与 JWT 形态字符串（无 key= 前缀时的兜底）。"""
    text = _BEARER_RE.sub("Bearer ***", text)
    return _JWT_RE.sub("***", text)


def sanitize_log(text: str | Any) -> str:
    """综合脱敏：对字符串内容进行多轮脱敏。

    脱敏顺序：手机号 → 邮箱 → 身份证 → 银行卡 → Bearer/JWT → 敏感 key=value
    """
    if not isinstance(text, str):
        text = str(text)
    text = mask_phone(text)
    text = mask_email(text)
    text = mask_idcard(text)
    text = mask_bankcard(text)
    text = mask_bearer_tokens(text)
    text = mask_sensitive_key_value(text)
    return text


def sanitize_dict(data: dict) -> dict:
    """递归脱敏字典中的敏感字段。"""
    result = {}
    for k, v in data.items():
        if isinstance(v, dict):
            result[k] = sanitize_dict(v)
        elif isinstance(v, str):
            # 对敏感字段名直接遮盖
            if _SENSITIVE_KEY_NAMES.match(k):
                result[k] = "******"
            else:
                result[k] = sanitize_log(v)
        else:
            result[k] = v
    return result
