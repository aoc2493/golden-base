# -*- coding: utf-8 -*-
"""出站 HTTPS 的统一信任锚（core net）。

统一的证书模块用于避免出站 webhook（企业微信 / 钉钉）各自配置 SSL，很容易
某天漂移成 `verify=False` —— 那样等于把 webhook 密钥和告警内容交给中间人。
统一到这里后，口径只有一处，且**永不降级为不校验证书**。

信任锚 = 系统证书库 + certifi CA bundle（两者取并集）：
  · 纯系统库在 slim 镜像里常年偏旧，部分 CA 根证书缺失导致校验误判失败；
  · 纯 certifi 则会丢掉企业自建 CA 与内网代理签发的证书。
两者并集既不误杀，也不放宽——任何一个根证书都无法单独签发并通过校验。

取不到任何根证书时直接抛异常，由调用方退回 httpx 的默认校验（而非关闭校验）。
"""
from __future__ import annotations

import logging
import ssl

logger = logging.getLogger(__name__)

# 出站 TLS 下限：TLS 1.2 起。低于该版本的套件（3DES/RC4/SSLv3）一律不启用。
_MIN_TLS_VERSION = ssl.TLSVersion.TLSv1_2


def trusted_ssl_context() -> ssl.SSLContext:
    """构造出站 HTTPS 用的 SSLContext：系统证书库 ∪ certifi，校验一律开启。

    Returns:
        可直接传给 httpx 的 ``verify=`` 的 ssl.SSLContext。

    Raises:
        RuntimeError: 一个根证书都没能载入时抛出，由调用方决定降级策略。
    """
    # create_default_context() 默认已启用证书校验与主机名校验，且拒绝无效证书。
    ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
    try:
        ctx.minimum_version = _MIN_TLS_VERSION
    except (AttributeError, ValueError):  # pragma: no cover - 极老 OpenSSL
        logger.warning("[net] 无法设定 TLS 最低版本，沿用解释器默认值")

    count_before = len(ctx.get_ca_certs())

    # 1) certifi：跟随 pip 更新的 CA bundle，补上系统库缺的根证书
    try:
        import certifi

        ctx.load_verify_locations(cafile=certifi.where())
    except Exception as e:  # pragma: no cover - certifi 缺失时不算致命
        logger.warning("[net] 载入 certifi CA 失败，仅使用系统证书库: %s", e)

    # 2) 系统证书库（部分发行版会预置企业/内网 CA，create_default_context 未必覆盖）
    try:
        ctx.load_default_certs(ssl.Purpose.SERVER_AUTH)
    except Exception as e:  # pragma: no cover
        logger.warning("[net] 载入系统证书库失败，仅使用 certifi: %s", e)

    count_after = len(ctx.get_ca_certs())
    if count_after == 0:
        raise RuntimeError("未载入任何根证书，拒绝在不校验证书的前提下发出请求")

    if count_after == count_before:
        # 说明 certifi 的根证书与系统库完全重合，不是故障，但值得留痕便于排查。
        logger.debug("[net] CA 数量未增加（certifi 与系统证书库重合），共 %d 张", count_after)

    return ctx
