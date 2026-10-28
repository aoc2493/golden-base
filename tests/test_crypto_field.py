"""A6 敏感字段加密（utils/crypto_field）的回归测试。

这个模块管的是「拖库之后收款账号与真实姓名是否还安全」，以及反过来更狠的一面：
**密文一旦被截断或换错密钥，那笔提现的收款人信息就永久不可恢复，钱也打不出去**。
两类失败都不会在界面上留下痕迹，所以必须用测试钉住：

1. 往返与随机 nonce（同明文两次密文不同，但都能解回）；
2. 篡改/换密钥/未配密钥三种退化路径各自的结局（展示路径给空串，打款路径必须抛）；
3. 列宽算式：按接口允许的最坏明文实测密文长度，必须塞得进落库列——
   原注释按「50 字符 ≈ 100 字符」放宽到 180，那是 ASCII 口径；姓名/账号字段并不限制字符集，
   50 个汉字是 150 字节，密文 247 字符，MySQL 严格模式直接 1406、非严格模式静默截断。
"""
import base64
import math

import pytest

from app.config import settings
from app.core.models import Distributor, Withdrawal
from app.core.schemas import WithdrawRequest
from app.core.utils import crypto_field as cf

CJK = "审计测试用长名字，用于压出最坏密文长度：汉字每个占三个字节。"


@pytest.fixture(autouse=True)
def _fresh_key_cache():
    """_derive_key 有进程级缓存：改了 settings 里的密钥必须清掉，否则用例互相污染。"""
    cf._KEY_CACHE = None
    yield
    cf._KEY_CACHE = None


def _max_len(model, field) -> int:
    info = model.model_fields[field]
    for m in info.metadata:
        if getattr(m, "max_length", None):
            return int(m.max_length)
    raise AssertionError(f"{model.__name__}.{field} 没有 max_length，最坏长度无法推算")


# ==================== 一、往返 ====================

@pytest.mark.parametrize("plain", [
    "张三", "欧阳娜娜", "ALIPAY 账号-示例@example.com", "6222020200112233445",
    "含 空格 与-符号_的@值", CJK, "a", "0",
])
def test_round_trip_preserves_exact_value(plain):
    """加解密必须逐字节还原：收款账号差一位就是把钱打给别人。"""
    enc = cf.encrypt_field(plain)
    assert cf.is_encrypted(enc), f"未加密落库: {enc!r}"
    assert enc != plain
    assert cf.decrypt_field(enc, strict=True, field="t") == plain


def test_same_plaintext_yields_different_ciphertext():
    """随机 nonce：同一条记录两次写入密文必须不同，否则密文本身可用于比对/枚举。"""
    a, b = cf.encrypt_field(CJK), cf.encrypt_field(CJK)
    assert a != b, "nonce 固定或被复用，等长明文会暴露相等关系"
    assert cf.decrypt_field(a) == cf.decrypt_field(b) == CJK


def test_empty_and_none_pass_through_unencrypted():
    """空值不加密：加密空串会让「有没有填过」这个事实需要解密才能判断。"""
    assert cf.encrypt_field(None) is None
    assert cf.encrypt_field("") == ""
    assert not cf.is_encrypted("")
    assert cf.decrypt_field(None) is None
    assert cf.decrypt_field("") == ""


def test_legacy_plaintext_is_returned_unchanged():
    """本次改动之前入库的明文没有前缀，必须原样可读（不做一次性迁移也能起服务）。"""
    assert cf.decrypt_field("张三", field="real_name") == "张三"
    assert not cf.is_encrypted("张三")


@pytest.mark.parametrize("value", [12345, 1.0, True])
def test_non_string_input_is_not_silently_dropped(value):
    """数字/布尔入参转成字符串加密后仍能读回，不能因为类型不是 str 就返回 None。"""
    enc = cf.encrypt_field(value)
    assert cf.is_encrypted(enc)
    assert cf.decrypt_field(enc) == str(value)


# ==================== 二、三条退化路径 ====================

def test_tampered_ciphertext_fails_loudly_and_never_returns_wrong_value(caplog):
    """改一个字节：GCM 认证标签必须让它解不开，而不是解出一个错误账号。

    这是本模块选 GCM 的唯一理由。返回「另一个看起来正常的字符串」比返回空串严重得多——
    运营会照着它打款。
    """
    import logging
    enc = cf.encrypt_field("6222020200112233445")
    raw = bytearray(base64.b64decode(enc[len("enc:v1:"):]))
    raw[-1] ^= 0xFF
    broken = "enc:v1:" + base64.b64encode(bytes(raw)).decode("ascii")
    with caplog.at_level(logging.CRITICAL):
        assert cf.decrypt_field(broken, field="account_no") == "", "篡改未被发现"
    assert "解密失败" in caplog.text
    with pytest.raises(ValueError):
        cf.decrypt_field(broken, strict=True, field="account_no")


def test_truncated_ciphertext_is_detected():
    """截断（列宽不够时的真实形态）必须解不开，而不是解出半串账号。"""
    enc = cf.encrypt_field(CJK)
    with pytest.raises(ValueError):
        cf.decrypt_field(enc[:len(enc) - 8], strict=True, field="account_name")


def test_other_key_cannot_decrypt(monkeypatch, caplog):
    """换密钥后旧密文解不开——这是「密钥丢失即数据丢失」的既有代价，必须响。

    用例锁的是行为而不是文案：静默返回空串而不告警，运维会以为「用户没填」。
    """
    import logging
    enc = cf.encrypt_field("张三")
    monkeypatch.setattr(settings, "SENSITIVE_FIELD_KEY", "another-sensitive-field-key-0123456789")
    cf._KEY_CACHE = None
    with caplog.at_level(logging.CRITICAL):
        assert cf.decrypt_field(enc) == ""
    assert "解密失败" in caplog.text


def test_key_derivation_is_aes256_over_sha256():
    """派生密钥必须是 sha256(SENSITIVE_FIELD_KEY) 的 32 字节，钉死而不是「能加解密就行」。

    起因（变异测试实跑出的存活变异）：把 `hashlib.sha256` 换成 `hashlib.md5` 后，
    全部往返用例照样绿——AESGCM 接受 16 字节密钥，等于悄悄降级成 AES-128；
    而下一次部署若再把派生方式换回去，库里所有密文都解不开（收款人永久丢失）。
    强度与「派生方式不可改」都是这个模块的承诺，必须各自有断言。
    """
    import hashlib

    secret = settings.SENSITIVE_FIELD_KEY
    assert secret, "用例依赖 conftest 已配好的密钥"
    key = cf._derive_key()
    assert len(key) == 32, f"密钥 {len(key)} 字节：AESGCM 会静默按 AES-128/AES-192 运行"
    assert key == hashlib.sha256(secret.encode("utf-8")).digest(), (
        "派生方式与 crypto_field 模块注释/SECURITY.md 口径不一致：换派生 = 换密钥，"
        "存量密文全部不可解，必须走密钥轮换流程而不是改这一行")


def test_missing_key_writes_plaintext_but_warns_once(monkeypatch, caplog):
    """未配密钥：降级写明文（不把提现整体打死）+ 一次性 CRITICAL 告警。

    告警只响一次是刻意的（列表页反复调用会淹掉真错误），但「响过一次」必须有测试钉住，
    否则改动成「完全不响」也没人发现。
    """
    import logging
    monkeypatch.setattr(settings, "SENSITIVE_FIELD_KEY", "")
    cf._KEY_CACHE = None
    cf._NO_KEY_WARNED = False
    try:
        with caplog.at_level(logging.CRITICAL):
            assert cf.encrypt_field("张三") == "张三", "无密钥时应降级写明文而不是抛异常"
            assert cf.encrypt_field("李四") == "李四"
        text = caplog.text
        assert "SENSITIVE_FIELD_KEY 未配置" in text
        assert text.count("以明文落库") == 1, "告警应只响一次（首次），不得逐次刷屏"
        # 无密钥时读到密文：展示路径给空串，打款路径必须抛，不能拿密文当姓名去审核
        assert cf.decrypt_field("enc:v1:AAAA", field="x") == ""
        with pytest.raises(ValueError):
            cf.decrypt_field("enc:v1:AAAA", strict=True, field="x")
    finally:
        cf._NO_KEY_WARNED = False
        cf._KEY_CACHE = None


# ==================== 三、脱敏口径 ====================

@pytest.mark.parametrize("plain,expect", [
    ("张", "张"),                      # 单字名不打星，打了反而像错字
    ("张三", "张*"),
    ("张三丰", "张**"),
    ("欧阳娜娜", "欧阳**"),            # 复姓/四字以上保留两字，留一字既没脱净又像错字
    ("司马相如AAA", "司马*****"),
])
def test_mask_name_keeps_surname_only(plain, expect):
    assert cf.mask_name(cf.encrypt_field(plain)) == expect


def test_mask_name_on_unreadable_ciphertext_is_empty():
    """解不开时脱敏结果是空串，绝不能把密文前缀或半截密文显示到后台列表上。"""
    assert cf.mask_name("enc:v1:not-valid-base64!!") == ""


def test_mask_account_matches_distribution_masking():
    """库里取出即脱敏，必须与 services/distribution 的明文口径同一结果——
    两处口径不一致时，后台列表和风控比对会给出两种说法。"""
    from app.core.services.distribution import mask_account as dist_mask
    plain_no = "13800001111"
    enc = cf.encrypt_field(plain_no)
    assert cf.mask_account("alipay", enc) == dist_mask("alipay", plain_no)


# ==================== 四、列宽算式（本轮新发现的风险） ====================

@pytest.mark.parametrize("model,column,schema_model,schema_field", [
    (Distributor, "real_name", WithdrawRequest, "account_name"),
    (Withdrawal, "account_name", WithdrawRequest, "account_name"),
    (Withdrawal, "account_no", WithdrawRequest, "account_no"),
])
def test_worst_case_ciphertext_fits_the_column(model, column, schema_model, schema_field):
    """接口允许的最坏明文，加密后必须放得进落库列。

    字段没有字符集限制，所以最坏情形按汉字算（UTF-8 每字 3 字节）。列宽不够时
    MySQL 严格模式报 1406 让整个提现事务失败，非严格模式静默截断——截断的密文
    永远解不开，这笔钱既打不出去也追不回收款人。

    断言口径是「列宽 ≥ 当前接口允许的最坏密文长」，不是「列宽必须等于 512」：
    把 real_name 改成 255 在本用例下不报错（最坏 247，仍够用），这是刻意的——
    真正会响的是接口 `max_length` 被放宽而列宽没跟上。
    """
    n = _max_len(schema_model, schema_field)
    width = model.__table__.c[column].type.length
    enc = cf.encrypt_field("字" * n)
    assert len(enc) <= width, (
        f"{model.__name__}.{column} 列宽 {width}，"
        f"但 {schema_model.__name__}.{schema_field} 允许的 {n} 个汉字"
        f"（{n * 3} 字节）加密后长 {len(enc)}：MySQL 1406 或静默截断")


def test_ciphertext_growth_formula_is_documented():
    """密文长度 = 前缀 7 + base64(nonce 12 + 明文 + tag 16)，随 UTF-8 字节数而非字符数增长。

    把算式写成断言，防止有人按「字符数」估算列宽（ASCII 口径）后放宽得不够。
    """
    plain = "字" * 10                      # 30 字节
    enc = cf.encrypt_field(plain)
    expect = len("enc:v1:") + 4 * math.ceil((12 + len(plain.encode()) + 16) / 3)
    assert len(enc) == expect, f"密文长度算式变了（{len(enc)} != {expect}），列宽需重算"
    ascii_enc = cf.encrypt_field("a" * 10)
    assert len(ascii_enc) < len(enc), "同字符数下 ASCII 明文更短：按字符估算列宽必然偏小"
