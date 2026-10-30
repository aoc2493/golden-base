# 依赖说明（原 requirements.txt 中文注释的移存处）

> 说明从 `requirements.txt` 移到这里的原因：中文注释无法被部分依赖解析工具正确读取，
> 导致 `pip-audit` / 部分依赖解析工具在读取该文件时崩溃（编码与解析器兼容问题），
> CI 里的漏洞扫描环节直接跑不起来。说明内容本身有价值，故移存到本文件，
> `requirements.txt` 只保留精简的英文注释。

## python-alipay-sdk（必须用它，不能用 alipay-sdk-python）

支付宝 SDK 必须用 `python-alipay-sdk`（提供 `from alipay import AliPay`）。

原写的 `alipay-sdk-python`（阿里官方 SDK）是**包名错误**：两者都占用顶层模块名 `alipay`，
但官方 SDK 的 `alipay/__init__.py` 只有 `name`/`__version__`、**没有 `AliPay` 类**，
会导致 `utils/payment.py` 的 `AlipayService._client()` 恒定 `ImportError`——
支付宝下单、回调验签、退款、查单全部静默失败
（下单表现为「支付创建失败」，回调被扣款后用户永不履约，退款重试 3 次后告警）。

两个包**不可共存**，切换时必须先卸载另一个。

## cryptography 版本对齐

`python-alipay-sdk` 经 `pyOpenSSL` 要求 `cryptography>=45`，原 43.0.1 会被 pip 自动升级。
这里显式对齐到实测可用版本，避免生产构建时出现「本地与镜像版本不一致」。

## 版本锁定策略

`requirements.txt` 全部使用 `==` 锁定，保证本地、CI、镜像三者一致。
升级依赖请在测试环境验证后再改，并同步执行 `pip-audit -r requirements.txt`。
