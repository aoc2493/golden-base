"""敏感字段（提现实名、收款人姓名、收款账号）落库加密。

敏感字段必须加密、而不能只做展示脱敏：脱敏只约束「显示」，库里仍是明文——一次拖库、
一份外泄的备份、一条误开的 SELECT 权限，就等于全量收款账号与真实姓名泄露。
《个人信息保护法》第五十一条要求对个人信息采取加密等安全技术措施，而收款账号一旦
泄露可直接造成资金损失（属敏感个人信息）。所以写入即加密、展示再脱敏，两层都要有。

算法：AES-256-GCM。cryptography 已是微信支付回调解密的既有依赖，不引入新包。
选 GCM 而不是 Fernet：这里需要的是「同一明文每次密文不同（随机 nonce）」+
「完整性校验」，GCM 的认证标签正好覆盖后者——密文被改动会在解密时直接抛异常，
而不是解出一个错误账号拿去打款；Fernet 的密文额外带时间戳且体积更大，无收益。

密文格式：enc:v1:<base64(nonce(12) || ciphertext || tag(16))>
带前缀是兼容存量的关键：尚未加密的历史明文没有前缀，解密时原样返回，
存量行无需一次性数据迁移即可继续读取；新写入一律带前缀。
版本号 v1 为将来换算法/换密钥留位（换密钥后旧密文解不开，见 decrypt_field 的告警）。

密钥：settings.SENSITIVE_FIELD_KEY，经 sha256 派生 32 字节 AES 密钥。
必须由配置提供而不能进程内随机生成：uvicorn 以 --workers 4 运行，四个进程各生成一把
密钥就会互相解不开对方写的数据。启动自检（main._startup_check）对其做 fail-closed 校验。
"""
import base64
import hashlib
import logging
import os

from app.config import settings

logger = logging.getLogger(__name__)

_PREFIX = "enc:v1:"
_NONCE_LEN = 12
# 明文列宽上限：加密后体积按 **UTF-8 字节数**（不是字符数）膨胀：
# 前缀 7 + base64(nonce 12 + 明文字节 + tag 16)。50 个汉字（150 字节）→ 247 字符，
# 100 个汉字（300 字节）→ 447 字符；同字符数的 ASCII 只有 111 / 151。
# 所以相关列宽按接口 max_length 允许的最坏明文实测取 512（口径常驻校验见
# tests/test_crypto_field.py::test_worst_case_ciphertext_fits_the_column，
# 存量库见 sql/migrations/0005_encrypted_field_width.sql）。
_KEY_CACHE = None
_NO_KEY_WARNED = False


def _derive_key():
    """从配置派生 AES-256 密钥。未配置时返回 None，由调用方决定降级方式。"""
    global _KEY_CACHE, _NO_KEY_WARNED
    if _KEY_CACHE is not None:
        return _KEY_CACHE
    secret = (settings.SENSITIVE_FIELD_KEY or "").strip()
    if not secret:
        # 只在首次触发时告警一次：提现/后台列表会反复调用，逐次刷日志会淹掉真正的错误。
        if not _NO_KEY_WARNED:
            _NO_KEY_WARNED = True
            logger.critical("SENSITIVE_FIELD_KEY 未配置，敏感字段将以明文落库（合规风险）。"
                            "请立即配置并重启；已入库的明文行可用 tools 脚本补加密。")
        return None
    _KEY_CACHE = hashlib.sha256(secret.encode("utf-8")).digest()
    return _KEY_CACHE


def is_encrypted(value) -> bool:
    """判断库里这一格是密文还是历史明文（按前缀，不做解密尝试）。"""
    return isinstance(value, str) and value.startswith(_PREFIX)


def encrypt_field(value) -> str:
    """加密一个敏感字段。

    空值原样返回：None/空串不是敏感信息，加密它只会让「有没有填过」这个事实变得
    需要解密才能判断，反而给风控比对（提现实名是否已绑定）添麻烦。
    未配置密钥时返回明文并留 critical 告警：宁可显式暴露配置缺失，也不要在
    没有密钥的情况下抛异常把提现功能整体打死——但告警必须响到运维能看见。
    """
    if value is None:
        return None
    text = str(value)
    if not text:
        return text
    key = _derive_key()
    if key is None:
        return text
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        nonce = os.urandom(_NONCE_LEN)
        ct = AESGCM(key).encrypt(nonce, text.encode("utf-8"), None)
        return _PREFIX + base64.b64encode(nonce + ct).decode("ascii")
    except Exception as e:  # pragma: no cover - 只在 cryptography 异常时触发
        logger.critical(f"敏感字段加密失败，将以明文落库（合规风险）: {e}")
        return text


def decrypt_field(value, *, strict: bool = False, field: str = ""):
    """解密一个敏感字段；历史明文原样返回。

    strict=False（默认，展示/脱敏路径）：解密失败返回空串。列表页因为一行坏数据
    整页 500 是不可接受的，坏行显示成空比打不开页面好。
    strict=True（打款路径）：解密失败直接抛异常。这里绝不能用一个兜底值继续走流程——
    把空账号或占位串交给运营去打款，比报错严重得多。
    解密失败通常只有两种成因：密钥被换过、或密文被篡改，两者都必须响到 critical。
    """
    if value is None:
        return None
    text = value if isinstance(value, str) else str(value)
    if not text.startswith(_PREFIX):
        return text
    key = _derive_key()
    if key is None:
        msg = f"敏感字段无法解密：SENSITIVE_FIELD_KEY 未配置 field={field or '?'}"
        if strict:
            raise ValueError(msg)
        logger.critical(msg)
        return ""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        raw = base64.b64decode(text[len(_PREFIX):])
        nonce, ct = raw[:_NONCE_LEN], raw[_NONCE_LEN:]
        return AESGCM(key).decrypt(nonce, ct, None).decode("utf-8")
    except Exception as e:
        msg = (f"敏感字段解密失败（密钥变更或密文被篡改）field={field or '?'}: "
               f"{type(e).__name__}")
        if strict:
            raise ValueError(msg) from e
        # 不打印密文与异常详情：密文本身是要保护的对象，异常里可能带明文片段。
        logger.critical(msg)
        return ""


def mask_name(value) -> str:
    """姓名脱敏：保留姓，其余按字数打星。先解密再脱敏（库里存的已经是密文）。
    复姓（欧阳/司马等）按前两字保留，避免「欧*」这种既没脱敏干净又像错字的输出。"""
    name = (decrypt_field(value, field="name") or "").strip()
    if not name:
        return ""
    if len(name) <= 1:
        return name
    keep = 2 if len(name) >= 4 else 1
    return name[:keep] + "*" * (len(name) - keep)


def mask_account(channel: str, value) -> str:
    """收款账号脱敏（解密后再脱敏）。口径与 services/distribution.mask_account 一致，
    那里保留明文入参是为了兼容调用方已解密的场景；本函数负责「库里取出即脱敏」。"""
    from app.core.services.distribution import mask_account as _mask
    return _mask(channel or "", decrypt_field(value, field="account_no") or "")
