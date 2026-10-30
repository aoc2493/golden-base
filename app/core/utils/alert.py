"""告警通道（企业微信群机器人 / 钉钉群机器人）。

独立告警模块用于把已有 ERROR 级留痕接到即时通道——[退款告警]（重试三次仍失败）、
[计佣告警]、[掉单补偿告警]（金额与渠道不符）、对账差错、启动自检阻断项——但没有一条会
主动推给人。日志躺在容器 stdout 里，得有人去 `docker compose logs` 才看得见；而资金类故障
的发现时延直接等于资损金额（退款重试耗尽意味着用户的钱卡在平台账上，每多一小时多一分投诉
与监管风险）。要做的不是「新增告警点」，而是把已有的 ERROR 接到即时通道上。

接入方式是一个 logging Handler（install_alert_handler），挂在 root logger 上，而不是在各
调用点逐个补 send_alert：散在调用点上必然漏（新增一处 logger.error 就得记得补一次），而漏掉
的那一处往往正是最严重的那个。Handler 方案下，任何模块（含 uvicorn / apscheduler /
sqlalchemy 等三方库）打的 ERROR 都会自动进通道，零改造、不会漏。

三条硬约束：
 1) 本模块自身的诊断日志一律 WARNING 及以下。Handler 只处理 ERROR，若发送失败时用
    logger.error 记录，就会「告警失败 → 触发告警 → 又失败」无限递归把机器人配额打满。
 2) 告警绝不阻断业务、绝不向调用方抛异常。通道自己挂了（网络/配额/webhook 失效）只记
    WARNING：因为告警发不出去而让退款流程失败，是把辅助系统变成了主链路的单点。
 3) 外发内容必须脱敏。群机器人是平台之外的第三方服务，把日志原文推过去等于向第三方提供
    个人信息（《个保法》第二十三条）。redact() 兜住手机号/证件号/银行卡/邮箱/字段密文；
    敏感个人信息原文不进入日志（风控日志只记录脱敏结果）。
"""
import asyncio
import base64
import hashlib
import hmac
import logging
import re
import socket
import time
import urllib.parse
from datetime import datetime
from typing import Optional, Tuple

import httpx

from app.config import settings

# 本模块的日志名。AlertHandler 会跳过它，防止「告警失败」再触发告警（见文件头约束 1）。
logger = logging.getLogger(__name__)

# 单次 HTTP 超时。告警是旁路，不能因为群机器人慢而把事件循环上的其他任务拖住；
# 企微/钉钉机器人在境内，3 秒足够，超时即放弃（下一条 ERROR 会再试）。
_TIMEOUT = 5.0

# ---------------- 外发内容脱敏 ----------------
# 两条约束互相牵制，少考一边都会出事：
# 【不能漏】手机号/证件号/银行卡/邮箱属个人信息，推给群机器人就是向第三方提供
#   （《个保法》第二十三条）。
# 【不能多】业务单号必须活着抵达运维手里。本项目里：
#   · 订单号 = "BZ" + 14 位时间戳 + 6 位随机数（共 20 位数字，见 utils/payment.generate_order_no）
#   · 微信 transaction_id / 支付宝 trade_no = 28 位纯数字
#   而银行卡号国标为 16~19 位。若把银行规则写成宽泛的 16~23 位、又不排除前面贴着
#   字母的情况，订单号的 20 位数字会正好落在区间内被当成银行卡打码——对账差错、
#   掉单金额不符这些告警里最关键的就是单号，打码之后运维根本无从查单，
#   告警变成「知道出事了但做不了任何事」，比不发还不如。
# 因此：长度窗口收紧到 16~19，且两端都要求不贴着字母/数字（单号恒带 BZ/RF 前缀）。
# 顺序也有意义：证件号（18 位）必须先于银行卡与手机号匹配，否则一串身份证号会被
# 银行卡规则截成两段、留下前 6 位地区码与后 4 位。
#
# 银行卡规则收紧后会不会漏掉真卡号？不会：已把 account_no/account_name 加密落库，
# 展示与日志一律走 mask_account/mask_name，明文卡号本就不应出现在日志里；
# 真出现时也是密文形态，由 _RE_CIPHER 兜住。
_RE_CIPHER = re.compile(r"enc:v1:[A-Za-z0-9+/=]{8,}")
_RE_IDCARD = re.compile(r"(?<![\dA-Za-z])(\d{6})(?:\d{8})(\d{3}[\dXx])(?![\dXx])")
_RE_BANK = re.compile(r"(?<![\dA-Za-z])(\d{4})\d{8,11}(\d{4})(?![\dA-Za-z])")
_RE_PHONE = re.compile(r"(?<![\dA-Za-z])(1[3-9]\d)\d{4}(\d{4})(?![\dA-Za-z])")
_RE_EMAIL = re.compile(r"([A-Za-z0-9._%+-]{1,2})[A-Za-z0-9._%+-]*@([A-Za-z0-9.-]+)")


def redact(text: str) -> str:
    """把日志文本里的个人信息与密文打码后再外发，同时保留业务标识符。

    只处理「形态可判定」的字段：手机号/证件号/银行卡/邮箱/加密字段密文，以及
    password=xxx / token: xxx / Bearer xxx / JWT 等密钥形态。
    复用 sanitizer 的 key=value 整体遮盖与 Bearer/JWT 兜底，避免敏感信息进入
    企业微信或钉钉第三方 webhook。
    姓名与身份证等字段不做泛化正则识别，避免误伤对账告警中的正常数字。
    必须保留的关键信息（bill_date 被打码后这条告警就没法处置了）。
    这两类信息按项目既有口径不写入日志。
    """
    if not text:
        return ""
    s = _RE_CIPHER.sub("enc:v1:***", text)
    s = _RE_IDCARD.sub(r"\1********\2", s)
    s = _RE_BANK.sub(r"\1********\2", s)
    s = _RE_PHONE.sub(r"\1****\2", s)
    s = _RE_EMAIL.sub(r"\1***@\2", s)
    from app.core.utils.sanitizer import mask_sensitive_key_value, mask_bearer_tokens
    s = mask_bearer_tokens(s)
    s = mask_sensitive_key_value(s)
    return s


# ---------------- 去重键归一 ----------------
_RE_HEX = re.compile(r"0x[0-9a-fA-F]{4,}")
_RE_DIGITS = re.compile(r"\d+")


def skeleton(msg: str) -> str:
    """把日志消息归一成「故障骨架」，作为去重键的一部分。

    同一次故障的每一条日志只在变量上不同（退款单 id、订单号、金额），直接用整条消息做键
    等于不去重：一轮调度里 20 条耗尽的退款单会发出 20 条告警，瞬间打满机器人配额。
    把数字与十六进制串替换成 # 之后，同一类故障收敛到同一个键，窗口内只发一条，
    并把「窗口内另有 N 条同类」随消息带出——既不刷屏，也不丢失规模信息。
    """
    s = _RE_HEX.sub("#", msg or "")
    s = _RE_DIGITS.sub("#", s)
    return s[:120]


# ---------------- 通道可用性 ----------------
def channels() -> dict:
    """已配置的通道（有序）。空 dict = 未接入任何通道。"""
    out = {}
    w = (settings.ALERT_WECOM_WEBHOOK or "").strip()
    d = (settings.ALERT_DINGTALK_WEBHOOK or "").strip()
    if w.startswith("http"):
        out["wecom"] = w
    if d.startswith("http"):
        out["dingtalk"] = d
    return out


def alert_ready() -> bool:
    """告警通道是否真正可用（总开关 + 至少一个合法 webhook）。

    启动自检与后台「发送测试告警」共用本判定：两处口径一旦分叉，就会出现自检说通了、
    实际一条也发不出去（或反之）的情况。
    """
    return bool(settings.ALERT_ENABLED) and bool(channels())


def env_tag() -> str:
    return (settings.ALERT_ENV_TAG or settings.APP_ENV or "production").strip()


def _host() -> str:
    """主机标识。容器里 hostname 就是容器 id 前 12 位，多副本部署时用它区分是哪一副本在报。"""
    try:
        return socket.gethostname()
    except Exception:  # pragma: no cover - 极少数沙箱环境取不到主机名
        return "unknown"


# ---------------- 运行统计（进程内） ----------------
# 心跳需要带上统计数据：如果只写「通道正常」，运维很快会当成噪声；带上
# 「本周期收到 N 条 ERROR、推送 M 条、抑制 K 条、失败 F 条」，一眼能分辨是「真没事」
# 还是「事很多但发不出去」（seen 远大于 sent 即通道有问题）。
# 只做进程内计数、不落库：这是给心跳与后台状态页用的即时指标，重启归零可接受；
# 为它建表等于把旁路系统做成有状态服务（多副本还得考虑归并），得不偿失。
_STATS = {"seen": 0, "sent": 0, "suppressed": 0, "failed": 0,
          "since": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}


def _bump(field: str, n: int = 1) -> None:
    """计数加一。不加锁：GIL 下 int 自增的竞态最坏丢一两次计数，而这是给人看的
    规模指标、不是对账数据；为它加锁反而会在每一条 ERROR 上引入额外开销。"""
    _STATS[field] = int(_STATS.get(field, 0) or 0) + n


def _snapshot_stats(reset: bool = False) -> dict:
    """读取统计；reset=True 同时归零并重置起算时点（心跳要报的是「本周期」的量，
    累计值只会越滚越大，最后变成一串没人看的数字）。"""
    st = dict(_STATS)
    if reset:
        for k in ("seen", "sent", "suppressed", "failed"):
            _STATS[k] = 0
        _STATS["since"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return st


# ---------------- 去重与风暴闸 ----------------
# Redis 故障时的进程内兜底。Redis 挂了本身就是需要告警的事，此时告警通道必须照常工作，
# 所以去重不能只依赖 Redis；单容器部署下进程内计数与 Redis 效果等价。
_LOCAL_DEDUP: dict = {}
_LOCAL_SUP: dict = {}
_LOCAL_MINUTE: dict = {}
_LOCAL_MAX_KEYS = 4096    # 容量上限：伪造海量不同日志把字典撑爆内存


def _local_prune(now: float) -> None:
    if len(_LOCAL_DEDUP) > _LOCAL_MAX_KEYS:
        for k in [k for k, exp in _LOCAL_DEDUP.items() if exp < now]:
            _LOCAL_DEDUP.pop(k, None)
            _LOCAL_SUP.pop(k, None)


async def _acquire_slot(key: str, force: bool) -> Tuple[bool, int]:
    """该次是否该发，以及去重窗口内被抑制了多少条同类。

    force=True 只跳过去重，不跳过风暴闸之外的任何校验——它用于「必须让人看到结果」的两处：
    启动自检失败（进程随即退出，被去重吞掉就等于没人知道服务没起来）与后台的测试告警按钮
    （运维点了没反应，无从判断是 webhook 配错还是被去重了）。
    """
    now = time.time()
    window = max(int(settings.ALERT_DEDUP_SECONDS or 0), 30)
    try:
        from app.core.auth import redis_client
        dk, sk = f"alert:dedup:{key}", f"alert:sup:{key}"
        if not force:
            got = await redis_client.set(dk, "1", nx=True, ex=window)
            if not got:
                await redis_client.incr(sk)
                await redis_client.expire(sk, window * 2)
                return False, 0
            raw = await redis_client.get(sk)
            if raw:
                await redis_client.delete(sk)
                return True, int(raw)
            return True, 0
        # force：仍要清掉去重键，否则这次强制发送之后，窗口内真正的同类故障会被误抑制
        await redis_client.delete(dk)
        await redis_client.delete(sk)
        return True, 0
    except Exception:
        pass
    # ---- 进程内兜底 ----
    _local_prune(now)
    if not force:
        exp = _LOCAL_DEDUP.get(key)
        if exp and exp > now:
            _LOCAL_SUP[key] = _LOCAL_SUP.get(key, 0) + 1
            return False, 0
        sup = _LOCAL_SUP.pop(key, 0)
        _LOCAL_DEDUP[key] = now + window
        return True, sup
    _LOCAL_DEDUP.pop(key, None)
    return True, _LOCAL_SUP.pop(key, 0)


async def _minute_gate(force: bool) -> bool:
    """全局每分钟配额闸。企微与钉钉机器人都是 20 条/分钟，超限直接封禁 10 分钟——
    被封期间任何新告警都发不出去，所以必须自己先卡在 10 条以内（ALERT_MAX_PER_MINUTE）。"""
    limit = max(int(settings.ALERT_MAX_PER_MINUTE or 0), 1)
    minute = int(time.time() // 60)
    try:
        from app.core.auth import redis_client
        mk = f"alert:min:{minute}"
        n = await redis_client.incr(mk)
        if n == 1:
            await redis_client.expire(mk, 120)
        return force or int(n) <= limit
    except Exception:
        pass
    for m in [m for m in _LOCAL_MINUTE if m < minute]:
        _LOCAL_MINUTE.pop(m, None)
    _LOCAL_MINUTE[minute] = _LOCAL_MINUTE.get(minute, 0) + 1
    return force or _LOCAL_MINUTE[minute] <= limit


# ---------------- 消息构造 ----------------
def build_message(title: str, detail: str, level: str, suppressed: int) -> str:
    """统一的消息正文（企微与钉钉的 markdown 子集一致，用同一份文本）。

    末行恒含「运行告警」四字：钉钉机器人若把安全设置选成「自定义关键词」而不是「加签」，
    消息必须包含关键词才会被投递；固定一个必然出现的词，比要求运维把关键词配成标题里的
    某个字更可靠（标题会随故障类型变化）。
    """
    limit = max(int(settings.ALERT_DETAIL_MAX_CHARS or 0), 200)
    body = redact((detail or "").strip())
    if len(body) > limit:
        body = body[:limit] + f"\n…（已截断，共 {len(body)} 字，完整内容见容器日志）"
    lines = [
        f"**【{env_tag()}·{level}】{redact(title or '未命名告警')}**",
        f"> 详情：{body or '（无）'}",
        f"> 主机：{_host()}",
        f"> 时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
    ]
    if suppressed > 0:
        lines.append(f"> 去重窗口内另有 {suppressed} 条同类被抑制（说明该类故障在持续发生）")
    # 署名取自配置而非写死产品名：同一套底座给不同业务使用时，
    # 告警来源必须显示各自的主体，否则会被误认为别的产品在报警。
    lines.append(f"> 来源：{settings.APP_NAME} 运行告警")
    return "\n".join(lines)


def _dingtalk_url() -> str:
    """钉钉加签。机器人安全设置选「加签」时，每次请求都要带 timestamp 与 HMAC-SHA256 签名；
    未配 secret 则原样返回（说明运维选的是关键词或 IP 白名单模式）。"""
    url = channels().get("dingtalk", "")
    secret = (settings.ALERT_DINGTALK_SECRET or "").strip()
    if not url or not secret:
        return url
    ts = str(round(time.time() * 1000))
    digest = hmac.new(secret.encode("utf-8"), f"{ts}\n{secret}".encode("utf-8"),
                      hashlib.sha256).digest()
    sign = urllib.parse.quote_plus(base64.b64encode(digest))
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}timestamp={ts}&sign={sign}"


def _ssl_context():
    """出站 webhook 的信任锚（core net：certifi + 系统证书库）。

    统一一处，不各写一份，避免证书校验口径漂移成 verify=False 把 webhook 密钥交给中间人。
    取不到时退回 httpx 默认校验，绝不关闭校验。
    """
    try:
        from app.core.utils.net import trusted_ssl_context
        return trusted_ssl_context()
    except Exception as e:  # pragma: no cover - net 导入失败的极端情形
        logger.warning("[告警] 信任锚获取失败，退回默认证书校验: %s", e)
        return True


async def _post(name: str, url: str, payload: dict) -> Optional[str]:
    """发一个通道。返回 None 表示成功，否则返回可读的失败原因。"""
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=_ssl_context()) as client:
            resp = await client.post(url, json=payload)
        if resp.status_code != 200:
            return f"{name} HTTP {resp.status_code}"
        try:
            data = resp.json()
        except Exception:
            return f"{name} 响应非 JSON: {resp.text[:120]}"
        # 两家都是 {"errcode":0,"errmsg":"ok"}；errcode 非 0 时 HTTP 仍是 200，
        # 只看状态码会把「关键词不匹配」「签名错误」「机器人被移除」全部当成发送成功。
        if int(data.get("errcode", 0) or 0) != 0:
            return f"{name} errcode={data.get('errcode')} errmsg={data.get('errmsg')}"
        return None
    except Exception as e:
        return f"{name} 发送异常: {type(e).__name__}: {str(e)[:160]}"


async def send_alert(title: str, detail: str = "", *, level: str = "ERROR",
                     key: Optional[str] = None, force: bool = False) -> dict:
    """发一条告警。返回 {sent, channels, errors, suppressed} 供调用方（含后台测试按钮）判断。

    任何异常都在内部消化：本函数被业务代码与 logging Handler 调用，向外抛一次就可能把
    退款/对账这类主流程打挂——告警是旁路，旁路不得成为主链路的单点。
    """
    result = {"sent": False, "channels": [], "errors": [], "suppressed": 0}
    if not settings.ALERT_ENABLED:
        return result
    ch = channels()
    if not ch:
        return result
    dedup_key = key or f"{skeleton(title)}|{skeleton(detail)}"
    # 标题也必须过 skeleton，不能只用它原文：真实日志的变量恰恰在首行
    # （「[退款告警] 退款单 id=101 已重试3次仍失败」），而 AlertHandler 正是拿首行当标题。
    # 只归一 detail 不归一 title，未显式传 key 的调用方就完全去不了重——
    # 一轮调度里 20 条耗尽的退款单依旧发 20 条，直接把机器人配额打满。
    try:
        ok, suppressed = await _acquire_slot(dedup_key, force)
        result["suppressed"] = suppressed
        if not ok:
            _bump("suppressed")
            return result
        if not await _minute_gate(force):
            _bump("suppressed")
            logger.warning("[告警] 已达每分钟上限 %s 条，本条被抑制: %s",
                           settings.ALERT_MAX_PER_MINUTE, title)
            return result
        content = build_message(title, detail, level, suppressed)
        for name, url in ch.items():
            if name == "dingtalk":
                payload = {"msgtype": "markdown",
                           "markdown": {"title": f"【{env_tag()}】{title[:40]}", "text": content}}
                target = _dingtalk_url()
            else:
                payload = {"msgtype": "markdown", "markdown": {"content": content}}
                target = url
            err = await _post(name, target, payload)
            if err:
                result["errors"].append(err)
                logger.warning("[告警] %s", err)
            else:
                result["channels"].append(name)
        result["sent"] = bool(result["channels"])
        if result["channels"]:
            _bump("sent")
        if result["errors"]:
            # 与 sent 可同时计数：两个通道一成一败时，既要看到「发出去了」，也要看到
            # 「备份通道已失效」。只记一边都会掩盖半边故障，而备份失效恰恰是最需要
            # 在主通道还好的时候就知道的事。
            _bump("failed")
        return result
    except Exception as e:  # pragma: no cover - 兜底，正常路径已逐层捕获
        _bump("failed")
        logger.warning("[告警] 投递失败（不影响业务）: %s", e)
        result["errors"].append(str(e)[:200])
        return result


# ---------------- logging 接入 ----------------
class AlertHandler(logging.Handler):
    """把 ERROR 及以上的日志记录转成即时告警。

    emit 是同步的，而发送是异步 httpx：有事件循环时 create_task 投递（uvicorn 与
    AsyncIOScheduler 的协程里都有），没有循环时退化为 asyncio.run 同步发一次——
    启动早期与独立脚本里的 ERROR 恰恰是最需要有人立刻知道的，不能因为没有循环就丢弃。
    """

    def emit(self, record: logging.LogRecord) -> None:
        try:
            if record.name == logger.name:
                return          # 自身诊断日志不再触发（防递归）
            _bump("seen")
            msg = record.getMessage()
            if record.exc_info:
                # 异常栈对定位是必需信息，但只取最后几帧：全栈动辄上千字，超出消息体也读不完
                msg = f"{msg}\n{logging.Formatter().formatException(record.exc_info)}"
            title = msg.strip().splitlines()[0][:80] if msg.strip() else record.name
            detail = msg
            key = f"{record.name}|{skeleton(msg)}"
            _dispatch(title, detail, record.levelname, key)
        except Exception:
            # logging 约定：Handler 内部异常绝不能向外抛，否则一次 logger.error 就把业务打成 500
            self.handleError(record)


def _dispatch(title: str, detail: str, level: str, key: str) -> None:
    coro = send_alert(title, detail, level=level, key=key)
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop is not None:
        loop.create_task(_guarded(coro))
        return
    try:
        asyncio.run(coro)
    except Exception as e:
        logger.warning("[告警] 同步投递失败: %s", e)


async def _guarded(coro) -> None:
    """create_task 的异常若无人 await 会打成「Task exception was never retrieved」噪音，
    统一在这里收口成一条 WARNING。"""
    try:
        await coro
    except Exception as e:
        logger.warning("[告警] 异步投递失败: %s", e)


_INSTALLED = False


def install_alert_handler() -> bool:
    """在 root logger 上挂 AlertHandler（幂等）。返回是否真正接入了通道。

    必须在 main.lifespan 的最前面调用（早于 _startup_check）：启动自检的阻断项是 ERROR，
    而那正是「服务起不来」这类最严重故障，晚挂一步就一条也发不出去。
    """
    global _INSTALLED
    if _INSTALLED:
        return alert_ready()
    _INSTALLED = True
    if not settings.ALERT_ENABLED:
        logger.info("[告警] ALERT_ENABLED=false，不接入告警通道")
        return False
    ch = channels()
    if not ch:
        logger.info("[告警] 未配置 ALERT_WECOM_WEBHOOK / ALERT_DINGTALK_WEBHOOK，"
                    "ERROR 日志仅落容器 stdout，不会主动推送")
        return False
    level = getattr(logging, (settings.ALERT_LEVEL or "ERROR").strip().upper(), logging.ERROR)
    logging.getLogger().addHandler(AlertHandler(level))
    logger.info("[告警] 已接入告警通道 %s（级别 %s，去重 %ss，每分钟上限 %s 条）",
                "/".join(ch), logging.getLevelName(level),
                settings.ALERT_DEDUP_SECONDS, settings.ALERT_MAX_PER_MINUTE)
    return True


# ---------------- 状态快照与每日心跳 ----------------
def _mask_url(url: str) -> str:
    """webhook 只回显末 8 位。完整地址里就带着机器人密钥（企微 key= / 钉钉 access_token=），
    把它下发到管理端页面等于：任何拿到管理令牌的人都能冒用机器人向全群发任意消息
    （伪造故障、钓鱼）。管理令牌本该只能读业务数据，不该顺带拿到一个对外发声的出口。"""
    u = (url or "").strip()
    return f"…{u[-8:]}" if u else ""


def status() -> dict:
    """告警通道状态快照。后台状态页与每日心跳共用本函数，避免两处口径分叉。"""
    ch = channels()
    st = _snapshot_stats()
    return {
        "enabled": bool(settings.ALERT_ENABLED),
        "ready": alert_ready(),
        "handler_installed": bool(_INSTALLED),
        "level": (settings.ALERT_LEVEL or "ERROR").strip().upper(),
        "env_tag": env_tag(),
        "host": _host(),
        "dedup_seconds": max(int(settings.ALERT_DEDUP_SECONDS or 0), 30),
        "max_per_minute": max(int(settings.ALERT_MAX_PER_MINUTE or 0), 1),
        "heartbeat": {"enabled": bool(settings.ALERT_HEARTBEAT_ENABLED),
                      "hour": int(settings.ALERT_HEARTBEAT_HOUR or 0) % 24},
        "channels": [{
            "name": n,
            "webhook_tail": _mask_url(u),
            # 加签只对钉钉有意义；企微机器人没有加签选项，统一报 False 而不是报错
            "signed": n == "dingtalk" and bool((settings.ALERT_DINGTALK_SECRET or "").strip()),
        } for n, u in ch.items()],
        "stats": {k: st.get(k, 0) for k in ("seen", "sent", "suppressed", "failed")},
        "stats_since": st.get("since"),
    }


async def heartbeat() -> dict:
    """每日心跳：证明通道本身可用，并带出本周期告警规模。

    不做成「只在有故障时才发」：那样「没消息」就同时可能是「系统正常」与「通道已断」，
    两者不可区分——而通道已断恰恰是在真出故障时才会被发现，那时已经晚了。
    心跳走的就是真告警同一条 _post 链路，所以它能验到的就是「现在能不能发出去」。
    """
    st = _snapshot_stats(reset=True)
    if not alert_ready():
        # 未接入时发不出去，只能记一条 WARNING 供排查「心跳没来」的原因（启动自检已提醒过）
        logger.warning("[告警] 心跳跳过：通道未就绪（ALERT_ENABLED=%s，已配合法 webhook %s 个）",
                       settings.ALERT_ENABLED, len(channels()))
        return {"sent": False, "skipped": True, "reason": "channel_not_ready"}
    ch = channels()
    detail = (
        f"统计周期自 {st.get('since') or '该次启动'} 起：\n"
        f"收到 ERROR/CRITICAL 日志 {st.get('seen', 0)} 条，实际推送 {st.get('sent', 0)} 条，"
        f"去重抑制 {st.get('suppressed', 0)} 条，推送失败 {st.get('failed', 0)} 条。\n"
        f"已接入通道：{'/'.join(ch)}；触发级别 {settings.ALERT_LEVEL}；"
        f"去重窗口 {settings.ALERT_DEDUP_SECONDS}s；每分钟上限 {settings.ALERT_MAX_PER_MINUTE} 条。\n"
        "判读：收到 0 条且本消息能收到 = 通道正常且无故障；"
        "收到大于 0 而推送为 0 = 通道已断，请立即核对机器人配置。"
    )
    # force=True 绕开去重：心跳的去重键天天相同，不 force 就会在窗口内被自己抑制
    return await send_alert("告警通道心跳（每日自检）", detail, level="INFO",
                            key="alert:heartbeat", force=True)
