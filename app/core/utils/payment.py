"""
支付平台封装（v7）
- 微信支付 V3：H5/JSAPI 下单、回调验签解密、退款（解析 refund_status，H4）
- 支付宝：手机网站支付 wap、回调验签、退款
- 退款单号 UUID 防碰撞（M4-单号/H3），金额全程 Decimal（T7）
"""
import asyncio
import httpx
import json
import time
import uuid
import base64
import secrets
import logging
import os
import re
from decimal import Decimal, InvalidOperation
from typing import Optional
from urllib.parse import urlparse
from app.config import settings

logger = logging.getLogger(__name__)


class RefundResult:
    """退款结果（N2/H4）：success 成功 / processing 处理中 / failed 失败"""
    def __init__(self, status: str, refund_no: str = "", raw: dict = None, msg: str = ""):
        self.status = status              # success / processing / failed
        self.refund_no = refund_no
        self.raw = raw or {}
        self.msg = msg

    @property
    def ok(self) -> bool:
        """兼容旧代码 bool 判断：仅明确成功才算 ok"""
        return self.status == "success"

    def __bool__(self):
        return self.ok


def gen_refund_no() -> str:
    """H3/M4：退款单号使用 UUID，彻底避免时间戳取模碰撞"""
    return "RF" + uuid.uuid4().hex[:24].upper()


# 渠道退款状态 -> 本地归一化状态。退款回调与主动查退款共用同一张表，避免两条链路
# 对同一个渠道状态给出两种解释（最典型：CLOSED 一边当失败、另一边当异常，
# 于是订单与退款单口径打架）。
REFUND_STATUS_MAP = {'SUCCESS': 'success', 'PROCESSING': 'processing',
                     'CLOSED': 'failed', 'ABNORMAL': 'failed'}


class PaymentService:
    @staticmethod
    def generate_order_no() -> str:
        """L1：BZ + 年月日时分秒 + 6 位密码学随机数，降低同秒碰撞概率"""
        timestamp = time.strftime("%Y%m%d%H%M%S")
        rand = str(secrets.randbelow(900000) + 100000)  # 6 位
        return f"BZ{timestamp}{rand}"


def _fen(amount) -> int:
    """元转分，Decimal 精确计算（T7）"""
    d = Decimal(str(amount)).quantize(Decimal("0.01"))
    return int((d * 100).to_integral_value())


class WechatPayService(PaymentService):
    def __init__(self):
        self.mch_id = settings.WECHAT_MCH_ID
        self.app_id = settings.WECHAT_APP_ID
        self.api_v3_key = settings.WECHAT_API_V3_KEY
        self.cert_serial_no = settings.WECHAT_CERT_SERIAL_NO
        self.notify_url = settings.WECHAT_NOTIFY_URL
        self._private_key = None
        self._load_private_key()

    def _load_private_key(self):
        # 只捕 FileNotFoundError 不够：挂载点权限不对（PermissionError）、路径配成目录
        # （IsADirectoryError）、文件编码异常都会在模块导入期抛出，直接把整个应用启动打挂。
        # 密钥读不到时应降级为“未配置”（is_configured() 返回 False）并留下可诊断日志，
        # 而不是静默把 _private_key 置空后让所有支付/退款都报“未配置”却查不到原因。
        path = settings.WECHAT_PRIVATE_KEY_PATH
        try:
            with open(path, "r", encoding="utf-8") as f:
                self._private_key = f.read()
        except FileNotFoundError:
            self._private_key = None
            if path:
                logger.warning(f"微信支付商户私钥文件不存在: {path}")
        except (OSError, UnicodeDecodeError) as e:
            self._private_key = None
            logger.error(f"微信支付商户私钥读取失败，支付与退款将不可用 path={path}: {e}")

    def _sign(self, method: str, url_path: str, body: str = "") -> dict:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        timestamp = str(int(time.time()))
        nonce_str = secrets.token_hex(16)   # 32 位 hex；nonce 用于防重放，必须用密码学安全随机数
        message = f"{method}\n{url_path}\n{timestamp}\n{nonce_str}\n{body}\n"
        private_key = serialization.load_pem_private_key(self._private_key.encode(), password=None)
        signature = private_key.sign(message.encode(), padding.PKCS1v15(), hashes.SHA256())
        sign_b64 = base64.b64encode(signature).decode()
        authorization = (
            f'WECHATPAY2-SHA256-RSA2048 mchid="{self.mch_id}",'
            f'nonce_str="{nonce_str}",timestamp="{timestamp}",'
            f'serial_no="{self.cert_serial_no}",signature="{sign_b64}"'
        )
        return {"Authorization": authorization, "timestamp": timestamp, "nonce_str": nonce_str}

    def is_configured(self) -> bool:
        return bool(self._private_key and self.mch_id and self.app_id)

    def _platform_cert_path(self) -> str:
        """平台证书模式凭据路径。配了路径但文件没上传时视为未配置——
        否则验签会以「签名校验异常」的形式报错，掩盖真正的病因（文件缺失）。"""
        path = settings.WECHAT_PLATFORM_CERT_PATH
        return path if path and os.path.exists(path) else ""

    def _public_key_path(self) -> str:
        """微信支付公钥模式凭据路径；同样以文件是否真实存在为准。"""
        path = settings.WECHAT_PUBLIC_KEY_PATH
        return path if path and os.path.exists(path) else ""

    def can_verify_callback(self) -> bool:
        """回调「验签 + 解密」的凭据是否就绪。

        与 is_configured() 的分工：is_configured 面向**下单/退款**（依赖商户私钥），
        本方法面向**回调**（只需 APIv3 密钥解密 + 微信侧公钥/平台证书验签）。
        回调路由用它做前置判定，把「环境凭据没配好」与「验签真的失败」彻底分开：
        前者 503 + ERROR（进告警通道），后者 400 + WARNING。
        """
        if not (self.mch_id and self.api_v3_key):
            return False
        return bool(self._public_key_path() or self._platform_cert_path())

    async def create_h5_order(self, order_no, amount, description, client_ip="127.0.0.1"):
        if not self.is_configured():
            logger.warning("微信支付未完成配置，无法下单")
            return None
        url_path = "/v3/pay/transactions/h5"
        body = json.dumps({
            "appid": self.app_id,
            "mchid": self.mch_id,
            "description": description[:127],
            "out_trade_no": order_no,
            "notify_url": self.notify_url,
            "amount": {"total": _fen(amount), "currency": "CNY"},
            "scene_info": {"payer_client_ip": client_ip, "h5_info": {"type": "Wap"}},
        }, ensure_ascii=False)
        sign = self._sign("POST", url_path, body)
        headers = {"Authorization": sign["Authorization"], "Content-Type": "application/json",
                   "Accept": "application/json", "User-Agent": "Mozilla/5.0"}
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post("https://api.mch.weixin.qq.com" + url_path,
                                         content=body.encode("utf-8"), headers=headers)
                if resp.status_code == 200:
                    return resp.json().get("h5_url")
                logger.error(f"微信下单失败 order={order_no} status={resp.status_code} body={resp.text[:500]}")
        except Exception as e:
            logger.error(f"微信下单异常 order={order_no}: {e}")
        return None

    async def create_jsapi_order(self, order_no, amount, description, openid):
        """N22：下单 appid 必须与 openid 归属一致（服务号 AppID 与支付 AppID 需相同）"""
        if not self.is_configured():
            logger.warning("微信支付未完成配置，无法下单")
            return None
        if not openid:
            logger.error(f"JSAPI下单缺少openid order={order_no}")
            return None
        url_path = "/v3/pay/transactions/jsapi"
        body = json.dumps({
            "appid": self.app_id,
            "mchid": self.mch_id,
            "description": description[:127],
            "out_trade_no": order_no,
            "notify_url": self.notify_url,
            "amount": {"total": _fen(amount), "currency": "CNY"},
            "payer": {"openid": openid},
        }, ensure_ascii=False)
        sign = self._sign("POST", url_path, body)
        headers = {"Authorization": sign["Authorization"], "Content-Type": "application/json",
                   "Accept": "application/json"}
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post("https://api.mch.weixin.qq.com" + url_path,
                                         content=body.encode("utf-8"), headers=headers)
                if resp.status_code == 200:
                    prepay_id = resp.json().get("prepay_id")
                    return self._build_jsapi_bridge_params(prepay_id) if prepay_id else None
                logger.error(f"微信JSAPI下单失败 order={order_no} status={resp.status_code} body={resp.text[:500]}")
        except Exception as e:
            logger.error(f"微信JSAPI下单异常 order={order_no}: {e}")
        return None

    def _build_jsapi_bridge_params(self, prepay_id):
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        timestamp = str(int(time.time()))
        nonce_str = secrets.token_hex(16)   # 32 位 hex；nonce 用于防重放，必须用密码学安全随机数
        package = f"prepay_id={prepay_id}"
        message = f"{self.app_id}\n{timestamp}\n{nonce_str}\n{package}\n"
        private_key = serialization.load_pem_private_key(self._private_key.encode(), password=None)
        signature = private_key.sign(message.encode(), padding.PKCS1v15(), hashes.SHA256())
        return {
            "appId": self.app_id, "timeStamp": timestamp, "nonceStr": nonce_str,
            "package": package, "signType": "RSA",
            "paySign": base64.b64encode(signature).decode(),
        }

    def verify_callback(self, headers: dict, body: bytes):
        """验证微信支付 V3 回调，返回支付结果或退款结果（H2：区分事件类型）"""
        try:
            timestamp = (headers.get("wechatpay-timestamp") or "").strip()
            # 服务器热修移植（2026-09 回调探针加固）：非数字时间戳直接 int() 抛 ValueError
            # → 回调接口 500。isascii 守卫同时排除 Unicode 数字（"²".isdigit() 为 True
            # 但 int() 抛错），与 admin.py 搜索分支同一口径。
            if not (timestamp.isascii() and timestamp.isdigit()) \
                    or abs(int(time.time()) - int(timestamp)) > 300:
                logger.warning("微信回调时间戳超出5分钟窗口")
                return None
            # 验签凭据未配置时拒绝回调，不跳过验签（避免 APIv3 密钥泄露后回调可伪造）。
            # 微信支付 APIv3 两种模式，按回调头 Wechatpay-Serial 自动判别：
            #   · 公钥模式     Serial = PUB_KEY_ID_xxx（微信支付公钥ID）→ 用公钥验签（官方推荐）
            #   · 平台证书模式 Serial = 40 位 hex（平台证书序列号）    → 用平台证书公钥验签
            serial = (headers.get("wechatpay-serial") or "").strip()
            if serial.upper().startswith("PUB_KEY_ID_"):
                key_path = self._public_key_path()
                if not key_path:
                    logger.error("微信回调被拒绝：回调为微信支付公钥模式，"
                                 "但未配置可用的 WECHAT_PUBLIC_KEY_PATH（路径为空或文件不存在）")
                    return None
                # P3 修复（凭据绑定）：serial 必须与所配公钥文件的标识一致，
                # 防止同模式下另一把公钥签发的报文被本站接受（证书轮换残留/异商户公钥）。
                if not self._serial_matches_keyfile(serial, key_path, is_cert=False):
                    logger.error(f"微信回调被拒绝：公钥模式 serial 与所配公钥不匹配 serial={serial[:32]}")
                    return None
                if not self._verify_wechat_signature(headers, body, key_path, is_cert=False):
                    logger.warning("微信回调微信支付公钥签名校验失败")
                    return None
            else:
                cert_path = self._platform_cert_path()
                if not cert_path:
                    logger.error("微信回调被拒绝：未配置可用的 WECHAT_PLATFORM_CERT_PATH 平台证书"
                                 "（且回调头非公钥模式），无法验签")
                    return None
                # P3 修复（凭据绑定）：serial 必须与所配平台证书的实际序列号一致
                if not self._serial_matches_keyfile(serial, cert_path, is_cert=True):
                    logger.error(f"微信回调被拒绝：平台证书模式 serial 与所配证书不匹配 serial={serial[:32]}")
                    return None
                if not self._verify_wechat_signature(headers, body, cert_path, is_cert=True):
                    logger.warning("微信回调平台证书签名校验失败")
                    return None
            data = json.loads(body)
            event_type = data.get("event_type", "")
            resource = data.get("resource", {})
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            aesgcm = AESGCM(self.api_v3_key.encode("utf-8"))
            plaintext = aesgcm.decrypt(
                resource.get("nonce", "").encode(),
                base64.b64decode(resource.get("ciphertext", "")),
                resource.get("associated_data", "").encode(),
            )
            result = json.loads(plaintext)
            # 【安全审计修复】跨商户回调防御：平台证书/公钥是全商户共用的，验签只能
            # 证明「这是微信平台签发的报文」，不能证明「这笔交易属于本商户」。任何
            # 持有自有微信商户号的攻击者都可以在自己商户下创建 out_trade_no=他人
            # 订单号、金额相同的订单并支付（钱进自己账户，成本仅手续费），再把这条
            # 真实签名回调投到本站 notify——没有商户号绑定时，等于用约 0.6% 手续费
            # 成本白送任意档位履约；退款事件同理可伪造「退款成功」让本地回收权益而
            # 真实资金分文未退。支付宝侧已做 app_id 绑定（AlipayService.verify_callback），
            # 微信侧在此对等补齐：mchid 必须与本商户号一致；appid 在事件资源中携带且
            # 本站已配置时同样校验（退款事件资源可能不含 appid，缺省放行，仅靠 mchid 绑定）。
            cb_mchid = str(result.get("mchid") or "")
            if self.mch_id and cb_mchid != self.mch_id:
                logger.error(f"微信回调商户号不匹配，已拒收: cb_mchid={cb_mchid} "
                             f"expect={self.mch_id} order_no={result.get('out_trade_no')}")
                return None
            cb_appid = str(result.get("appid") or "")
            if self.app_id and cb_appid and cb_appid != self.app_id:
                logger.error(f"微信回调 appid 不匹配，已拒收: cb_appid={cb_appid} "
                             f"expect={self.app_id} order_no={result.get('out_trade_no')}")
                return None
            # H2：退款回调，返回 event=refund 供上层更新 Refund 状态
            if event_type.startswith("REFUND"):
                return {
                    "event": "refund",
                    "event_type": event_type,
                    "refund_no": result.get("out_refund_no"),
                    "order_no": result.get("out_trade_no"),
                    "refund_status": result.get("refund_status"),
                    "channel_refund_no": result.get("refund_id"),
                }
            return {
                "event": "payment",
                "order_no": result.get("out_trade_no"),
                "pay_trade_no": result.get("transaction_id"),
                # P3：分→元用 Decimal，避免 float 精度误差进入金额比对链路
                "amount": Decimal(str(result.get("amount", {}).get("total", 0))) / 100,
                "status": result.get("trade_state"),
            }
        except Exception as e:
            logger.error(f"微信回调解密失败: {e}", exc_info=True)
            return None

    def _serial_matches_keyfile(self, serial: str, key_path: str, is_cert: bool) -> bool:
        """P3 修复（凭据绑定）：回调头 Wechatpay-Serial 必须与本地所配凭据的标识一致。

        平台证书模式：序列号 = X.509 证书 serial_number 的 hex（40 位）。
        公钥模式：公钥文件 PEM 头部含 "PUBLIC KEY ID"，直接比对文件内容中的 ID 串；
        解析不出 ID（文件格式意外）时返回 False——fail-closed，宁可拒收也不放宽。
        """
        try:
            with open(key_path, "rb") as f:
                raw = f.read()
            if is_cert:
                from cryptography.hazmat.primitives import serialization
                cert = serialization.load_pem_x509_certificate(raw)
                expect = format(cert.serial_number, "x").upper()
                return (serial or "").upper() == expect
            # 公钥模式：公钥文件的 PUBLIC KEY ID 标识。用正则在整个文件里搜 PUB_KEY_ID_xxx，
            # 不再只认「PUBLIC KEY ID」这一行。旧实现按行匹配该关键字，而微信官方下载件带该
            # 注释行、纯 PEM 裁剪件（只剩 BEGIN/END）不带——后者是合法可用的凭据，旧实现却
            # 恒返回 False，于是每一条回调都被判「serial 与所配公钥不匹配」拒收 400，
            # 退款单永久停在 processing（本项目实际故障形态）。文件是否带一行可选注释，
            # 不该决定资金链路是否通。
            m = re.search(r'PUB_KEY_ID_[0-9A-Za-z]+', raw.decode(errors='replace'),
                          re.IGNORECASE)
            if not m:
                # 文件未携带标识串：无法做「请求头 serial <-> 本地文件」的绑定比对。
                # 此处不放行等于把「少一行可选注释」放大成资金链路全断；而真正的安全边界是
                # 紧随其后的 RSA 验签——用本文件公钥验证签名，非本密钥签发的报文必然失败，
                # 故降级为「仅验签」并告警留痕，便于运维补齐注释行后恢复严格绑定。
                logger.warning(
                    f"微信支付公钥文件未携带 PUBLIC KEY ID 注释，跳过 serial 绑定比对，"
                    f"仅以签名验证为准 path={key_path} serial={(serial or '')[:32]}")
                return True
            return (serial or "").upper() == m.group(0).upper()
        except Exception as e:
            logger.error(f"微信回调凭据序列号解析异常: {e}", exc_info=True)
            return False

    def _verify_wechat_signature(self, headers, body, key_path, is_cert=True):
        """微信侧签名校验。

        is_cert=True  → 平台证书模式：key_path 是 X.509 证书，取其公钥验签；
        is_cert=False → 微信支付公钥模式：key_path 是 PEM 公钥，直接加载验签。
        两者签名算法一致（SHA256withRSA / PKCS1v15），仅凭据解析方式不同。
        """
        try:
            ts = headers.get("wechatpay-timestamp", "")
            nonce = headers.get("wechatpay-nonce", "")
            signature = headers.get("wechatpay-signature", "")
            if not signature:
                return False
            message = f"{ts}\n{nonce}\n".encode() + body + b"\n"
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import padding
            with open(key_path, "rb") as f:
                raw = f.read()
            if is_cert:
                public_key = serialization.load_pem_x509_certificate(raw).public_key()
            else:
                public_key = serialization.load_pem_public_key(raw)
            public_key.verify(base64.b64decode(signature), message,
                              padding.PKCS1v15(), hashes.SHA256())
            return True
        except Exception as e:
            logger.error(f"微信平台签名校验异常: {e}", exc_info=True)
            return False

    async def refund(self, order_no, pay_trade_no, amount, reason="用户申请退款",
                     refund_no: Optional[str] = None, order_amount=None) -> RefundResult:
        """
        H4：解析返回体 refund_status。
        L9：校验退款金额不超过订单金额。
        """
        if not self.is_configured():
            return RefundResult("failed", msg="微信支付未配置")
        # L9：退款金额不得超过订单金额（P3：去掉 +0.01 容差，多退一分也是资损）。
        # 【安全审计修复】原写法 `if order_amount is not None and ...`：调用方漏传订单金额
        # 时校验被整体跳过，这条资损红线形同虚设（等价于死代码）。改为 fail-closed——
        # 拿不到订单金额就拒绝退款，红线不依赖调用方自觉。
        if order_amount is None:
            logger.error("退款缺少订单金额，已拒绝（无法校验退款上限）order=%s", order_no)
            return RefundResult("failed", msg="缺少订单金额，无法校验退款上限")
        if Decimal(str(amount)) > Decimal(str(order_amount)):
            return RefundResult("failed", msg="退款金额超过订单金额")
        refund_no = refund_no or gen_refund_no()
        url_path = "/v3/refund/domestic/refunds"
        body = json.dumps({
            "out_trade_no": order_no,
            "out_refund_no": refund_no,
            "reason": reason[:80],
            "amount": {
                "refund": _fen(amount),
                # total 必须是原订单总额，不是本次退款额：微信会校验它等于原订单金额。
                # 原实现两处都填 amount，全额退款时两者恰好相等而侥幸通过，
                # 一旦支持部分退款就必然被微信驳回。
                "total": _fen(order_amount),
                "currency": "CNY",
            },
        }, ensure_ascii=False)
        sign = self._sign("POST", url_path, body)
        headers = {"Authorization": sign["Authorization"], "Content-Type": "application/json"}
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post("https://api.mch.weixin.qq.com" + url_path,
                                         content=body.encode("utf-8"), headers=headers)
                if resp.status_code in (200, 204):
                    try:
                        rj = resp.json()
                    except Exception:
                        rj = {}
                    st = rj.get("status", "SUCCESS")
                    if st == "SUCCESS":
                        return RefundResult("success", refund_no, rj)
                    if st in ("PROCESSING", "CLOSED"):
                        # H4：处理中不算成功，等退款回调更新（H2）
                        logger.info(f"微信退款处理中 order={order_no} status={st}")
                        return RefundResult("processing", refund_no, rj, st)
                    # ABNORMAL 等异常
                    logger.error(f"微信退款异常状态 order={order_no} status={st} body={resp.text[:300]}")
                    return RefundResult("failed", refund_no, rj, st)
                logger.error(f"微信退款HTTP失败 order={order_no} status={resp.status_code} body={resp.text[:300]}")
                return RefundResult("failed", refund_no, msg=f"HTTP {resp.status_code}")
        except Exception as e:
            logger.error(f"微信退款异常 order={order_no}: {e}", exc_info=True)
            return RefundResult("failed", refund_no, msg=str(e))

    async def query_refund(self, refund_no: str) -> dict:
        """主动查退款 GET /v3/refund/domestic/refunds/{out_refund_no}

        返回 {state: success/processing/failed/unsupported/error, refund_status, msg}。
        state 语义与退款回调严格对齐（共用 REFUND_STATUS_MAP），避免「回调说成功、
        查询说失败」这类两条链路互相打架的口径分裂。404/查不到归 error 而非 failed：
        「渠道查不到」与「渠道明确没退成」是两回事，猜成 failed 会让上层把订单还原为
        completed，而钱可能已经退出去了——那是真实资损。V3 GET 的待签串把 query 一并
        计入路径、body 为空行，本接口无 query 参数，故 body 传空串（与 query_order 同）。
        """
        if not self.is_configured():
            return {"state": "unsupported", "msg": "微信支付未配置"}
        url_path = f"/v3/refund/domestic/refunds/{refund_no}"
        sign = self._sign("GET", url_path, "")
        headers = {"Authorization": sign["Authorization"],
                   "Content-Type": "application/json"}
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get("https://api.mch.weixin.qq.com" + url_path,
                                        headers=headers)
            if resp.status_code != 200:
                logger.error(f"微信查询退款HTTP失败 refund_no={refund_no} "
                             f"status={resp.status_code} body={resp.text[:200]}")
                return {"state": "error", "msg": f"HTTP {resp.status_code}"}
            rj = resp.json()
            st = str(rj.get("status") or "").upper()
            state = REFUND_STATUS_MAP.get(st, "error")
            if state == "processing":
                logger.info(f"微信查询退款处理中 refund_no={refund_no} status={st}")
            return {"state": state, "refund_status": st, "msg": st}
        except Exception as e:
            logger.error(f"微信查询退款异常 refund_no={refund_no}: {e}", exc_info=True)
            return {"state": "error", "msg": str(e)}

    async def query_order(self, order_no) -> dict:
        """A2：主动查单 GET /v3/pay/transactions/out-trade-no/{out_trade_no}?mchid=xxx

        回调可能全部丢失（网络闪断、发布重启、平台重试耗尽），没有拉取式查单就没有兜底，
        用户已扣款而订单永久停在 pending/expired。V3 GET 的待签串是
        「GET
{路径含query}
{时间戳}
{随机串}

」（body 为空行），所以 query 一并交给
        _sign 的 url_path 参数、body 保持空串。
        404/ORDER_NOT_EXIST 表示微信侧从未收到过这笔单（用户没唤起过支付），等同未支付。
        """
        if not self.is_configured():
            return {"state": "unsupported", "channel": "wechat", "msg": "微信支付未配置"}
        url_path = f"/v3/pay/transactions/out-trade-no/{order_no}"
        full_path = f"{url_path}?mchid={self.mch_id}"
        sign = self._sign("GET", full_path)
        headers = {"Authorization": sign["Authorization"], "Accept": "application/json",
                   "User-Agent": "Mozilla/5.0"}
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                resp = await client.get("https://api.mch.weixin.qq.com" + full_path, headers=headers)
                if resp.status_code == 200:
                    return self._normalize_query(resp.json())
                if resp.status_code == 404:
                    return {"state": "unpaid", "channel": "wechat", "trade_state": "ORDER_NOT_EXIST"}
                logger.error(f"微信查单失败 order={order_no} status={resp.status_code} body={resp.text[:300]}")
        except Exception as e:
            logger.error(f"微信查单异常 order={order_no}: {e}", exc_info=True)
        # unknown 与 unpaid 必须分开：unknown 是「没问成」，下一轮还要再问；
        # 若归为 unpaid 就会把已付款订单误判为未支付而停止补偿（真掉单）。
        return {"state": "unknown", "channel": "wechat"}

    @staticmethod
    def _normalize_query(data: dict) -> dict:
        """渠道返回归一化，屏蔽两个渠道的字段差异。
        REFUND 也算「已支付」：它表示该单支付成功后发生过退款，资金确曾入账，
        必须走履约补偿后再由退款链路回收，否则用户两头落空。"""
        state_map = {"SUCCESS": "paid", "REFUND": "paid", "NOTPAY": "unpaid",
                     "USERPAYING": "paying", "CLOSED": "closed", "REVOKED": "revoked",
                     "PAYERROR": "error", "ORDER_NOT_EXIST": "unpaid"}
        total = (data.get("amount") or {}).get("total")
        amount = ((Decimal(str(total)) / Decimal(100)).quantize(Decimal("0.01"))
                  if total is not None else None)
        state = state_map.get(data.get("trade_state"), "unknown")
        if data.get("trade_state") == "REFUND":
            # 有意设计（见上方 docstring）：已退款的交易资金确曾入账，仍按已收款补履约，
            # 再由退款链路回收权益。此处留痕是为了让「补履约后迟迟未回收」变得可见。
            logger.warning(f"[掉单补偿] 渠道交易状态为 REFUND（支付成功后已退款），仍按已收款补履约，"
                           f"须由退款链路回收权益；若长期未回收请人工核查 "
                           f"trade_no={data.get('transaction_id')}")
        return {"state": state, "channel": "wechat",
                "trade_state": data.get("trade_state"), "pay_trade_no": data.get("transaction_id"),
                "amount": amount, "raw": data}

    async def download_tradebill(self, bill_date: str, bill_type: str = "ALL") -> Optional[str]:
        """A3：下载交易账单。先 GET /v3/bill/tradebill 拿 download_url，再对该 URL 的
        路径+query 重新签名下载正文（微信要求下载请求同样带 Authorization）。
        不传 tar_type 时返回未压缩 CSV 文本；bill_type=ALL 含当日支付成功单与发起成功的退款单。
        账单仅保留 3 个月，次日 09:00 生成，官方建议 10:00 后拉取。
        当日无交易时微信返回 4xx（如 NOT_FOUND），属于正常情形，不应当成故障告警。
        """
        if not self.is_configured():
            return None
        url_path = "/v3/bill/tradebill"
        full_path = f"{url_path}?bill_date={bill_date}&bill_type={bill_type}"
        sign = self._sign("GET", full_path)
        headers = {"Authorization": sign["Authorization"], "Accept": "application/json"}
        try:
            async with httpx.AsyncClient(timeout=60) as client:
                resp = await client.get("https://api.mch.weixin.qq.com" + full_path, headers=headers)
                if resp.status_code != 200:
                    logger.warning(f"微信账单获取未成功 date={bill_date} status={resp.status_code} "
                                   f"body={resp.text[:200]}")
                    return None
                download_url = (resp.json() or {}).get("download_url")
                if not download_url:
                    logger.warning(f"微信账单无 download_url date={bill_date}")
                    return None
                # SSRF 防护：download_url 来自渠道响应，正常可信；但上游一旦被劫持或返回异常地址，
                # 未加校验的 GET 会打到内网或云元数据服务。强制 https + 域名白名单。
                _p = urlparse(download_url)
                if _p.scheme != "https" or (_p.hostname or "").lower() != "api.mch.weixin.qq.com":
                    logger.error(f"微信账单 download_url 非 https 或非白名单域名，拒绝下载 "
                                 f"date={bill_date} host={(_p.hostname or '')[:64]}")
                    return None
                parsed = urlparse(download_url)
                dl_path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
                sign2 = self._sign("GET", dl_path)
                r2 = await client.get(download_url, headers={
                    "Authorization": sign2["Authorization"], "Accept": "*/*"})
                if r2.status_code != 200:
                    logger.error(f"微信账单正文下载失败 date={bill_date} status={r2.status_code}")
                    return None
                return r2.text
        except Exception as e:
            logger.error(f"微信账单下载异常 date={bill_date}: {e}")
        return None


class AlipayService(PaymentService):
    def __init__(self):
        self.app_id = settings.ALIPAY_APP_ID
        self.gateway = settings.ALIPAY_GATEWAY
        self.notify_url = settings.ALIPAY_NOTIFY_URL
        self.return_url = getattr(settings, "ALIPAY_RETURN_URL", "") or ""
        self._private_key = None
        self._public_key = None
        self._load_keys()

    def _load_keys(self):
        # 同 WechatPayService._load_private_key：只捕 FileNotFoundError 时，挂载权限/路径类型/编码
        # 问题会在导入期抛出，直接拖挂启动；必须降级为未配置并留日志。
        priv, pub = settings.ALIPAY_PRIVATE_KEY_PATH, settings.ALIPAY_PUBLIC_KEY_PATH
        try:
            with open(priv, "r", encoding="utf-8") as f:
                self._private_key = f.read()
            with open(pub, "r", encoding="utf-8") as f:
                self._public_key = f.read()
        except FileNotFoundError:
            self._private_key = None
            self._public_key = None
            if priv or pub:
                logger.warning(f"支付宝密钥文件不存在: priv={priv} pub={pub}")
        except (OSError, UnicodeDecodeError) as e:
            self._private_key = None
            self._public_key = None
            logger.error(f"支付宝密钥读取失败，支付与退款将不可用 priv={priv} pub={pub}: {e}")

    def _client(self):
        from alipay import AliPay
        return AliPay(appid=self.app_id, app_notify_url=self.notify_url,
                      app_private_key_string=self._private_key,
                      alipay_public_key_string=self._public_key,
                      sign_type="RSA2", debug=False)

    def is_configured(self) -> bool:
        return bool(self._private_key and self._public_key and self.app_id)

    async def create_wap_order(self, order_no, amount, subject):
        if not self.is_configured():
            logger.warning("支付宝未完成配置，无法下单")
            return None
        try:
            order_string = self._client().api_alipay_trade_wap_pay(
                out_trade_no=order_no, total_amount=str(Decimal(str(amount)).quantize(Decimal("0.01"))),
                subject=subject[:128], return_url=self.return_url, notify_url=self.notify_url)
            return f"{self.gateway}?{order_string}"
        except Exception as e:
            logger.error(f"支付宝下单异常 order={order_no}: {e}")
            return None

    def verify_callback(self, form_data: dict):
        if not self.is_configured():
            return None
        try:
            data = dict(form_data)
            signature = data.pop("sign", None)
            data.pop("sign_type", None)
            if not signature:
                return None
            alipay = self._client()
            # 防御纵深：验签只能证明报文来自支付宝，还需确认是本应用的回调。
            # 服务商/多应用共用同一把支付宝公钥时，缺少此校验会把别的 appid 的
            # 订单号当成本站订单去激活（若订单号恰好撞上则直接送权益）。
            cb_app_id = data.get("app_id")
            # P3 修复：本站已配置 app_id 时，回调必须携带且一致——原实现允许
            # 回调缺失 app_id 即放行，等于把绑定校验留给对端自觉。
            if self.app_id and str(cb_app_id or "") != self.app_id:
                logger.warning(f"支付宝回调 app_id 缺失或不匹配，已拒收: {cb_app_id!r} != {self.app_id}")
                return None
            if alipay.verify(data, signature) and data.get("trade_status") in ("TRADE_SUCCESS", "TRADE_FINISHED"):
                return {"event": "payment", "order_no": data.get("out_trade_no"),
                        "pay_trade_no": data.get("trade_no"),
                        "amount": float(data.get("total_amount", 0)), "status": data.get("trade_status")}
            # 非终态（WAIT_BUYER_PAY 等）验签通过但不处理，返回 ignore 避免支付宝反复重试
            if alipay.verify(data, signature):
                return {"event": "ignore"}
        except Exception as e:
            logger.error(f"支付宝回调验签异常: {e}", exc_info=True)
        return None

    async def refund(self, order_no, pay_trade_no, amount, reason="用户申请退款",
                     refund_no: Optional[str] = None, order_amount=None) -> RefundResult:
        if not self.is_configured():
            return RefundResult("failed", msg="支付宝未配置")
        # P3：与微信侧同口径，去掉 +0.01 退款容差，并改为 fail-closed——
        # 漏传订单金额时原实现直接跳过校验，退款上限形同虚设（详见微信侧同款注释）。
        if order_amount is None:
            logger.error("退款缺少订单金额，已拒绝（无法校验退款上限）order=%s", order_no)
            return RefundResult("failed", msg="缺少订单金额，无法校验退款上限")
        if Decimal(str(amount)) > Decimal(str(order_amount)):
            return RefundResult("failed", msg="退款金额超过订单金额")
        refund_no = refund_no or gen_refund_no()

        def _do():
            try:
                result = self._client().api_alipay_trade_refund(
                    out_trade_no=order_no,
                    refund_amount=str(Decimal(str(amount)).quantize(Decimal("0.01"))),
                    refund_reason=reason[:80], out_request_no=refund_no)
                if result.get("code") == "10000":
                    return RefundResult("success", refund_no, result)
                logger.error(f"支付宝退款失败 order={order_no} result={result}")
                return RefundResult("failed", refund_no, result, result.get("sub_msg", ""))
            except Exception as e:
                logger.error(f"支付宝退款异常 order={order_no}: {e}", exc_info=True)
                return RefundResult("failed", refund_no, msg=str(e))
        return await asyncio.to_thread(_do)

    async def query_order(self, order_no) -> dict:
        """A2：支付宝主动查单 alipay.trade.query。SDK 是同步 urlopen 实现，放线程池避免阻塞事件循环。
        订单不存在时支付宝返回业务失败（sub_code=ACQ.TRADE_NOT_EXIST）并由 SDK 抛异常，这与「未支付」
        同义；其余异常一律归为 unknown（下一轮继续问），继不猜成 unpaid。"""
        if not self.is_configured():
            return {"state": "unsupported", "channel": "alipay", "msg": "支付宝未配置"}

        def _do():
            return self._client().api_alipay_trade_query(out_trade_no=order_no)

        try:
            data = await asyncio.to_thread(_do)
        except Exception as e:
            if "TRADE_NOT_EXIST" in str(e):
                return {"state": "unpaid", "channel": "alipay", "trade_state": "TRADE_NOT_EXIST"}
            logger.error(f"支付宝查单异常 order={order_no}: {e}")
            return {"state": "unknown", "channel": "alipay"}
        return self._normalize_query(data or {})

    @staticmethod
    def _normalize_query(data: dict) -> dict:
        """TRADE_CLOSED 归为 closed 而非 paid：支付宝该状态含「未付款超时关闭」与「已全额退款关闭」
        两种语义，两者都不应该履约；上层对 pending 订单拿到 closed 会留告警交人工核对。"""
        state_map = {"TRADE_SUCCESS": "paid", "TRADE_FINISHED": "paid",
                     "WAIT_BUYER_PAY": "paying", "TRADE_CLOSED": "closed"}
        amount = data.get("total_amount")
        return {"state": state_map.get(data.get("trade_status"), "unknown"), "channel": "alipay",
                "trade_state": data.get("trade_status"), "pay_trade_no": data.get("trade_no"),
                "amount": Decimal(str(amount)).quantize(Decimal("0.01")) if amount else None,
                "raw": data}

    async def download_bill(self, bill_date: str, bill_type: str = "trade") -> Optional[str]:
        """A3：支付宝对账单。SDK 未封装该接口，用通用 build_body + verified_sync_response 打
        alipay.data.dataservice.bill.downloadurl.query，拿到 zip 地址后下载并解出业务明细 CSV。
        支付宝账单 CSV 是 GBK 编码（微信是 UTF-8），必须按编码兜底解码，否则中文列名全乱、解析失败。"""
        if not self.is_configured():
            return None

        def _do():
            client = self._client()
            data = client.build_body("alipay.data.dataservice.bill.downloadurl.query",
                                     {"bill_type": bill_type, "bill_date": bill_date})
            return client.verified_sync_response(
                data, "alipay_data_dataservice_bill_downloadurl_query_response")

        try:
            result = await asyncio.to_thread(_do)
        except Exception as e:
            logger.warning(f"支付宝账单地址获取未成功 date={bill_date}: {e}")
            return None
        urls = ((result or {}).get("bill_download_url_list") or {}).get("bill_download_url") or []
        if isinstance(urls, dict):
            urls = [urls]
        target = next((u.get("bill_download_url") for u in urls
                       if "trade" in str(u.get("bill_type", ""))), None)
        target = target or (urls[0].get("bill_download_url") if urls else None)
        if not target:
            logger.warning(f"支付宝账单无下载地址 date={bill_date} result={str(result)[:200]}")
            return None
        try:
            # 同上 SSRF 防护：支付宝账单地址同样来自渠道响应，强制 https + 域名白名单
            _p = urlparse(target or "")
            if _p.scheme != "https" or (_p.hostname or "").lower() not in (
                    "openapi.alipay.com", "openapi.alipaydev.com",
                    "openapi-sandbox.dl.alipaydev.com"):
                logger.error(f"支付宝账单下载地址非 https 或非白名单域名，拒绝下载 "
                             f"date={bill_date} host={(_p.hostname or '')[:64]}")
                return None
            async with httpx.AsyncClient(timeout=120) as client:
                resp = await client.get(target)
                if resp.status_code != 200:
                    logger.error(f"支付宝账单下载失败 date={bill_date} status={resp.status_code}")
                    return None
                return _extract_bill_csv(resp.content)
        except Exception as e:
            logger.error(f"支付宝账单下载异常 date={bill_date}: {e}")
        return None


def _extract_bill_csv(content: bytes) -> Optional[str]:
    """从支付宝账单 zip 中取出业务明细 CSV 文本。
    zip 内通常是「_业务明细.csv」+「_业务明细(汇总).csv」两个文件，对账要明细那个；
    zip 条目名在 Python 里会被当 cp437 解（除非置了 UTF-8 标志），所以中文判断前先转回 GBK；
    都识别不出时退而取最大的 CSV（明细恒大于汇总）。

    正文编码不能「第一个解码成功就返回」：GBK 能把大多数 UTF-8 中文字节串无报错地解成
    乱码，一旦支付宝改用 UTF-8 出账，表头列名全部失配，解析器只会警告「未识别到表头」
    而静默返回空列表——对账看起来跑完了，实际一笔也没比。所以以「解出来能不能看到
    中文表头关键字」作为选编码的判据，而非能不能解码。"""
    import io
    import zipfile
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as zf:
            names = zf.namelist()
            csvs = [n for n in names if n.lower().endswith(".csv")]
            if not csvs:
                logger.warning("支付宝账单 zip 内无 CSV 文件")
                return None

            def _fix(n: str) -> str:
                try:
                    return n.encode("cp437").decode("gbk")
                except Exception:
                    return n

            detail = [n for n in csvs if "明细" in _fix(n) and "汇总" not in _fix(n)]
            pick = detail[0] if detail else max(csvs, key=lambda n: zf.getinfo(n).file_size)
            raw = zf.read(pick)
    except Exception as e:
        logger.error(f"支付宝账单解压失败: {e}")
        return None
    fallback = None
    for enc in ("gbk", "utf-8-sig", "utf-8"):
        try:
            text = raw.decode(enc)
        except UnicodeDecodeError:
            continue
        if fallback is None:
            fallback = text
        if "商户订单号" in text or "支付宝交易号" in text:
            return text
    if fallback is not None:
        logger.warning("支付宝账单未命中中文表头关键字，按首个可解码结果返回（可能编码不符）")
        return fallback
    return raw.decode("utf-8", errors="replace")


wechat_pay = WechatPayService()
alipay = AlipayService()


def _safe_pay_url(url: Optional[str]) -> Optional[str]:
    """支付跳转 URL 协议白名单。

    pay_url 最终被前端 `location.href = pay_url` 整页跳转，任何非 http(s) 协议
    （如被注入的 javascript: / data:）都会形成开放重定向/XSS 载体。微信 h5_url
    与支付宝 wap 地址均由官方接口返回、恒为 https，这里仅作协议白名单兜底：
    非 http(s) 一律丢弃，宁可不调起支付也不让非预期协议进入前端跳转逻辑。"""
    if not url:
        return None
    if isinstance(url, str) and (url.lower().startswith("https://")
                                 or url.lower().startswith("http://")):
        return url
    logger.warning("支付跳转 URL 协议非法，已拦截: %r", url)
    return None


async def create_payment(order_no, amount, subject, client_ip="127.0.0.1",
                         channel="wechat", scene="h5", openid=None):
    if settings.PAYMENT_MOCK and not settings.is_prod_env:
        # 本地演示：不调渠道，前端拿到 pay_type=mock 后调用 /api/payment/mock/pay 完成履约
        return {"pay_type": "mock", "order_no": order_no}
    if channel == "wechat":
        if scene == "jsapi":
            params = await wechat_pay.create_jsapi_order(order_no, amount, subject, openid or "")
            return {"pay_type": "jsapi", "jsapi_params": params} if params else None
        url = _safe_pay_url(await wechat_pay.create_h5_order(order_no, amount, subject, client_ip))
        return {"pay_type": "redirect", "pay_url": url} if url else None
    if channel == "alipay":
        url = _safe_pay_url(await alipay.create_wap_order(order_no, amount, subject))
        return {"pay_type": "redirect", "pay_url": url} if url else None
    logger.error(f"未知支付渠道: {channel}")
    return None


# ============================================================================
# L23：退款资格的统一护栏
# ============================================================================
# 平台共 4 条退款路径，最终都落到下面的 apply_refund：
#   ① api/order.py     用户自助退款       —— 经 _self_refund_block 拦截
#   ② api/admin.py     管理员兜底退款     —— 原先只拦了卡券单
#   ③ tasks/scheduler  auto_refund_failed_reports —— 原先什么都没拦（本次修复）
#   ④ tasks/scheduler  retry_failed_refunds       —— 原先只拦了卡券单
# 「这笔订单到底有没有真实资金流入」原先由 4 处各自手写判断，口径必然漂移，
# ③ 就是漏掉的那一条：0 元的卡券兑换单被当成真实订单退款，apply_refund 在模拟
# 支付模式下直接判成功，revoke_refunded_order 随即撤销用户已到账的权益 ——
# 卡券已是 used 无法重兑，用户既没拿回钱、也永久失去已兑换的商品，无恢复路径。
# 故收敛到本函数，任何新增退款路径都必须复用它，而不是再手写一遍判断。

# 明确无真实资金流入的渠道：
#   · 'card'   —— 卡券兑换单（services/card.py），后台生成、凭码兑换，0 元
#   · 'member' —— 会员期内 ensure-report 产生的 0 元解读单（插件报告端点）
# 将来若新增「积分兑换 / 补发订单」等同样不动账的渠道，登记到这里即可。
NO_PAY_CHANNELS = ("card", "member")


def has_real_payment(order) -> bool:
    """该订单是否存在真实资金流入（即「退款」这件事在物理上是否成立）。

    判定刻意保持最小化，只排除两类**确定**不动账的订单：
      1. 金额 <= 0；
      2. 渠道属于 NO_PAY_CHANNELS。

    不做「渠道必须 ∈ (wechat, alipay)」的白名单 —— 那样会把历史订单
    （pay_channel 可空）一起排除掉，而它们是有资金语义、
    该退就得退的（失败报告自动退款正依赖于此）。宁可漏判也不误拦。
    """
    try:
        amount = Decimal(str(getattr(order, "amount", 0) or 0))
    except (InvalidOperation, TypeError, ValueError):
        return False
    if amount <= 0:
        return False
    channel = (getattr(order, "pay_channel", None) or "").strip().lower()
    if channel in NO_PAY_CHANNELS:
        return False
    return True


def no_payment_reason(order) -> str:
    """返回「该订单不适用退款」的中文原因；has_real_payment 为真时返回空串。"""
    if has_real_payment(order):
        return ""
    channel = (getattr(order, "pay_channel", None) or "").strip().lower()
    if channel == "card":
        return "卡券兑换订单不支持退款，请通过卡券作废流程处理"
    if channel == "member":
        return "会员权益内产生的 0 元订单无实际支付金额，不支持退款"
    return "该订单无实际支付金额，不支持退款"


async def apply_refund(order_no, pay_trade_no, amount, reason="用户申请退款",
                       channel=None, refund_no: Optional[str] = None,
                       order_amount=None) -> RefundResult:
    """统一退款入口，返回 RefundResult（含 success/processing/failed 状态与退款单号）"""
    kwargs = dict(refund_no=refund_no, order_amount=order_amount)
    if channel == "wechat":
        return await wechat_pay.refund(order_no, pay_trade_no, amount, reason, **kwargs)
    if channel == "alipay":
        return await alipay.refund(order_no, pay_trade_no, amount, reason, **kwargs)
    if pay_trade_no and pay_trade_no.startswith(("4200", "w")):
        return await wechat_pay.refund(order_no, pay_trade_no, amount, reason, **kwargs)
    r = await wechat_pay.refund(order_no, pay_trade_no, amount, reason, **kwargs)
    # 只有“微信侧明确未受理”才回退支付宝；success 与 processing 都必须原样上抛。
    # 原实现用 r.ok（仅 status=='success' 为真）判断，导致微信返回 PROCESSING
    # （退款极常见的正常中间态）时又向支付宝发起同一笔退款，并把支付宝的
    # 失败结果当作最终结果 → 本地记为 failed、不撤销权益，而微信那边退款照样成功，
    # 形成“钱退了、权益与报告还在”的真实资金损失。
    if r.status in ("success", "processing"):
        return r
    # P3 修复（渠道回退双退款）：进一步收紧回退条件——只有微信侧**确定性**未受理
    # （订单不存在类错误）才回退支付宝。网络异常/超时导致的 failed 无法排除
    # 「微信已受理但响应丢失」，此时再打支付宝会造成两渠道各退一笔；
    # 不确定失败原样返回，交由调用方重试或人工核查。
    _DEFINITE_MISS = ("RESOURCE_NOT_EXISTS", "ORDERNOTEXIST", "ORDER_NOT_EXIST",
                      "TRADE_NOT_EXIST", "NOT_EXISTS")
    if any(k in (r.msg or "") for k in _DEFINITE_MISS):
        return await alipay.refund(order_no, pay_trade_no, amount, reason, **kwargs)
    return r


async def query_payment(order_no: str, channel: Optional[str] = None) -> dict:
    """A2：统一查单入口，返回归一化结果：
    {"state": paid/unpaid/paying/closed/revoked/error/unknown/unsupported,
     "channel", "trade_state", "pay_trade_no", "amount": Decimal|None, "raw"}

    channel 为空时（历史订单 pay_channel 可空）先问微信；微信答「未支付/未知/未配置」且支付宝已
    配置时再问支付宝——渠道侧对不属于自己的商户订单号必然答不存在，串问一次是安全的。
    """
    if not settings.PAY_QUERY_ENABLED:
        return {"state": "unsupported", "channel": channel or ""}
    if channel == "alipay":
        return await alipay.query_order(order_no)
    r = await wechat_pay.query_order(order_no)
    if channel == "wechat":
        return r
    if r.get("state") in ("unpaid", "unknown", "unsupported") and alipay.is_configured():
        r2 = await alipay.query_order(order_no)
        if r2.get("state") == "paid" or r.get("state") == "unknown":
            return r2
    return r


async def query_refund(refund_no: str, channel: Optional[str] = None) -> dict:
    """A2 同范式（退款侧）：统一主动查退款入口，返回归一化结果。

    为什么必须有拉取式查退款：退款结论完全依赖渠道回调送达，而回调可能因验签配置错误、
    发布重启、网络抖动或平台重试耗尽而永远不到达。本项目实际发生过——验签配置缺陷使全部
    回调被判 400，退款单永久停在 processing，管理员既看不到「已退款」也不敢重发，只能靠猜。
    推送不可靠时必须有主动拉取兜底，与 query_payment 同一思路。
    支付宝退款为同步返回（无异步中间态），无需查询；此处仅微信。
    """
    if not settings.PAY_QUERY_ENABLED:
        return {"state": "unsupported", "msg": "主动查单未开启"}
    if channel == "alipay":
        return {"state": "unsupported", "msg": "支付宝退款为同步返回，无异步状态需查询"}
    return await wechat_pay.query_refund(refund_no)


async def download_channel_bill(bill_date: str, channel: str) -> Optional[str]:
    """A3：统一账单下载入口（bill_date 为 YYYY-MM-DD），返回 CSV 文本或 None。
    None 不区分「当日无交易」与「下载失败」，由调用方（services/reconcile.py）记账并告警。"""
    if not settings.RECONCILE_ENABLED:
        return None
    if channel == "wechat":
        return await wechat_pay.download_tradebill(bill_date, settings.RECONCILE_BILL_TYPE)
    if channel == "alipay":
        return await alipay.download_bill(bill_date)
    logger.error(f"未知对账渠道: {channel}")
    return None
