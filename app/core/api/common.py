"""通用响应辅助 + 安全工具（真实IP/原子限流/金额/脱敏）"""
import secrets
import hmac
import time
import logging
from decimal import Decimal
from fastapi import Request
from fastapi.responses import JSONResponse
from typing import Any
from app.config import settings

logger = logging.getLogger(__name__)


def success(data: Any = None, msg: str = "success") -> dict:
    return {"code": 0, "msg": msg, "data": data}


def error(code: int, msg: str, data: Any = None) -> JSONResponse:
    return JSONResponse(status_code=200, content={"code": code, "msg": msg, "data": data})


# 错误码常量
class ErrorCode:
    SUCCESS = 0
    SERVER_ERROR = 5000
    PARAM_ERROR = 1001
    NOT_LOGIN = 1002
    NO_PERMISSION = 1003
    RATE_LIMIT = 1004
    FILE_INVALID = 1005
    # 会员功能配额用尽（自然日/自然月）。与 RATE_LIMIT 分开：1004 是「每分钟防刷」，
    # 文案「请稍后再试」；本码是「今日次数用尽，明天再试」，前端据此弹专门的提示框，
    # 混进 1004 会让用户以为等几秒就能重试。
    QUOTA_EXCEEDED = 1006
    # 年龄门槛与未成年人保护（services/minor_guard）。三个码分开是因为前端的应对
    # 完全不同，归进 PARAM_ERROR 就只能弹一句「参数错误」，用户不知道下一步该做什么：
    #   1007 需先完成成年声明 → 弹出生日期表单，提交后重放原请求；
    #   1008 需补一项确认（监护人同意 / 他人出生信息告知）→ 弹勾选框，data.gate 区分是哪一种；
    #   1009 终态：声明为未成年人，禁止充值，没有任何可操作项。
    # data 里带门槛文案（后端下发，前端不另抄）：门槛文案是向用户作出的承诺，抄两份必然走偏。
    AGE_GATE_REQUIRED = 1007
    CONSENT_REQUIRED = 1008
    MINOR_BLOCKED = 1009
    # 第五十七/五十八条：用户提交的 UGC（昵称/反馈等）命中一级敏感词被拦截。
    # 独立于 PARAM_ERROR：这不是参数格式错，而是内容违规，前端可据此弹合规提示并引导修改，
    # 与后台敏感词告警口径对齐。二级预警词不占用本码（放行 + 文字提示）。
    CONTENT_VIOLATION = 1010
    CACHE_EXPIRED = 3001
    CACHE_NOT_FOUND = 3002
    PRODUCT_NOT_FOUND = 4001
    ORDER_INVALID = 4002
    REFUND_DISABLED = 4003
    REFUND_NOT_ELIGIBLE = 4004
    PAYMENT_FAILED = 4005
    REFUND_FAILED = 4006
    # 电子发票。三个码分开的原因同上——前端应对完全不同，
    # 归进 PARAM_ERROR 就只能弹一句「参数错误」：
    #   4007 该订单不满足开票条件（未支付/已退款/超自助窗口）→ 灰掉按钮并说明原因；
    #   4008 已申请过 → 直接把用户带到那条申请记录，而不是让他再填一遍表单；
    #   4009 开票入口整体关闭 → 提示联系客服，表单填了也提交不上去。
    INVOICE_NOT_ELIGIBLE = 4007
    INVOICE_DUPLICATED = 4008
    INVOICE_DISABLED = 4009
    UPLOAD_FAILED = 5002
    # 敏感字段解密失败（密钥被更换或密文被篡改）。单独一个码而不归入 PARAM_ERROR：
    # 这不是用户传错了参数，重试也没用，必须人工介入核对密钥；后台据此码弹“联系技术”
    # 而不是“请重新提交”，也不会把密文当收款账号显示出来。
    SENSITIVE_DECRYPT_FAILED = 5003
    ADMIN_LOCKED = 6001
    # CSRF 校验失败：跨站请求伪造被拦截。前端应据此清掉本地会话并跳登录。
    CSRF_FAILED = 6002


class AdminAuthDenied(Exception):
    """管理端鉴权失败（无令牌 / 令牌错误 / 该 IP 已被锁定 / 不在 IP 白名单）。

    此前 require_admin 用“返回 False”表达失败，路由体再 return error(ADMIN_LOCKED, ...)，
    于是鉴权失败也走 HTTP 200（业务码 6001）——nginx 访问日志、监控告警、WAF 看到的
    失败尝试与成功访问完全一样，令牌爆破在传输层不可观测。
    改为抛出本异常，由 main.py 统一回 HTTP 401 + code=6001：传输层可见失败，
    前端语义不变（管理端前端同时兼容 HTTP 401/403 与 code=6001）。
    """
    def __init__(self, msg: str = "管理令牌无效或已被锁定"):
        super().__init__(msg)
        self.msg = msg


def get_client_ip(request: Request) -> str:
    """
    获取用户真实公网 IP。
    nginx 反代后 request.client.host 是容器内网 IP，必须读代理头；
    但直连部署（uvicorn 直接对外，如本机开发/轻量部署）时，X-Real-IP 与
    X-Forwarded-For 完全由客户端控制，无条件信任会让所有 IP 维度防护
    （注册限流、下单限流、管理令牌爆破锁定 admin_fail:{ip}）被一个伪造头绕过。
    因此仅在显式声明 TRUST_PROXY_HEADERS=true（确定部署在会覆写这些头的可信反代之后）
    时才采纳代理头，否则一律用 TCP 对端地址。

    同机进程绕过 IP 白名单：服务绑定 127.0.0.1:8000 且信任代理头时，同机任意进程
    仍可直连后端并伪造 X-Real-IP 绕过全部 IP 防护。配置 PROXY_AUTH_SECRET 后，
    还要求请求携带反代注入的 X-Proxy-Auth 共享密钥（hmac 常量时间比对），
    三者齐备才信任代理头——伪造头在直连场景彻底失效。密钥不配置则维持原行为（兼容）。
    """
    peer = request.client.host if request.client else "0.0.0.0"
    if not settings.TRUST_PROXY_HEADERS:
        return peer
    secret = (getattr(settings, "PROXY_AUTH_SECRET", "") or "").strip()
    if secret:
        supplied = request.headers.get("X-Proxy-Auth", "")
        if not hmac.compare_digest(supplied.encode(), secret.encode()):
            # 未携带/不匹配：视为不可信直连，退回 TCP 对端地址（不报错——
            # 后端健康检查等本机探测不应被 5xx 打挂）
            return peer
    # nginx 配置为 proxy_set_header X-Real-IP $remote_addr，由代理直接覆写，可信度最高
    xri = request.headers.get("X-Real-IP")
    if xri and xri.strip():
        return xri.strip()
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        # nginx 配置为 $proxy_add_x_forwarded_for（追加模式），XFF = 「客户端伪造值..., 真实IP」：
        # 最右侧一段由可信代理追加，取它才能避免伪造首位绕过限流/锁定。
        # 注：此结论以“单级可信反代”为前提；若前面还挂了 CDN/WAF 多层代理，
        # 需改为从右数第 N 段（N = 可信代理层数）。
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        if parts:
            return parts[-1]
    return peer


# Redis 原子限流：用 Lua 保证「清窗+计数+写入」原子。
# 滑动窗口：原实现是 INCR+EXPIRE 的固定窗口——窗口边界处可叠加两个窗口的配额，
# 最坏 2 倍突发（例如限 10/min，在 00:59 打 10 次、01:00 再打 10 次，2 秒内 20 次全放行）。
# 改为滑动日志（ZSET，score=毫秒时间戳）：每次请求先剔除窗口外成员再计数，
# 任意连续 window 秒内最多 limit 次，彻底消除边界突发；代价是每键一个 ZSET（成员随请求增长，
# 但窗口过期后整键 EXPIRE 回收，内存可控）。
_LUA_SLIDING = """
local key = KEYS[1]
local limit = tonumber(ARGV[1])
local window_ms = tonumber(ARGV[2]) * 1000
local now_ms = tonumber(ARGV[3])
-- 兼容旧版固定窗口遗留的 STRING 键：ZREMRANGEBYSCORE 遇非 ZSET 会抛 WRONGTYPE，
-- 异常走到 REDIS_FAIL_CLOSED=true 的降级拦截会把登录/下单全部挡死（上线窗口期真实可触发）。
-- 类型不符直接删键重建：旧键只剩最多一个窗口的计数，丢弃不影响安全语义。
if redis.call('TYPE', key).ok ~= 'zset' then
    redis.call('DEL', key)
end
redis.call('ZREMRANGEBYSCORE', key, '-inf', now_ms - window_ms)
local current = redis.call('ZCARD', key)
if current >= limit then
    return 0
end
redis.call('ZADD', key, now_ms, now_ms .. '-' .. math.random(1, 1000000000))
redis.call('PEXPIRE', key, window_ms)
return 1
"""


async def redis_rate_limit(redis_client, key: str, limit: int, window_seconds: int) -> bool:
    """滑动窗口限流：任意连续 window_seconds 内超过 limit 返回 False（被限流），否则 True（放行）。
    Redis 故障时的降级策略由 settings.REDIS_FAIL_CLOSED 控制——
    False 放行避免拖垮主流程；True（默认，安全优先）拦截，防止故障窗口内无限速。
    「Redis 从未配置」（redis_client=None，sqlite 轻量/开发模式）不属于故障：直接放行，
    否则无 Redis 部署会被 fail-closed 全部拦死。"""
    if redis_client is None:
        return True
    try:
        now_ms = int(time.time() * 1000)
        allowed = await redis_client.eval(
            _LUA_SLIDING, 1, key, str(limit), str(window_seconds), str(now_ms))
        return bool(allowed)
    except Exception as e:
        logger.warning(f"限流器异常，{'降级拦截' if settings.REDIS_FAIL_CLOSED else '降级放行'} key={key}: {e}")
        return not settings.REDIS_FAIL_CLOSED


# 释放锁必须比对令牌：Lua 保证「GET 比对 + DEL」原子，不会误删他人刚抢到的锁
_LUA_RELEASE_LOCK = """
if redis.call('GET', KEYS[1]) == ARGV[1] then
    return redis.call('DEL', KEYS[1])
end
return 0
"""
# Redis 故障降级放行时返回的哨兵令牌：本次根本没写进 Redis，释放时必须直接跳过，
# 否则一旦 Redis 在请求期间恢复，DELETE 会把别人正在持有的锁删掉。
_DEGRADED_LOCK_TOKEN = "__redis_degraded__"


async def redis_acquire_lock(redis_client, key: str, ttl_seconds: int,
                             fail_closed: bool | None = None) -> str:
    """SETNX 互斥锁：抢到返回锁令牌（非空字符串），未抢到返回空串。
    用于堆叠数据库唯一约束拦不住的并发重复入口
    （如并发创建两张不同订单、各自触发一次付费第三方 API）。
    TTL 必须给足：进程崩溃时靠 TTL 自动释放，不会永久死锁。Redis 故障默认遵循
    REDIS_FAIL_CLOSED；确有独立数据库护栏的调用方可显式选择降级放行。

    返回值由 bool 改为令牌字符串，`if not await redis_acquire_lock(...)` 的判空写法不变；
    令牌必须原样传给 redis_release_lock，否则释放会静默失效（宁可留到 TTL 过期）。"""
    token = secrets.token_urlsafe(24)
    if redis_client is None:
        return _DEGRADED_LOCK_TOKEN
    try:
        ok = await redis_client.set(key, token, nx=True, ex=ttl_seconds)
        return token if ok else ""
    except Exception as e:
        should_close = settings.REDIS_FAIL_CLOSED if fail_closed is None else fail_closed
        if should_close:
            logger.error("互斥锁异常，按 fail-closed 拒绝进入临界区 key=%s: %s",
                         key, e)
            return ""
        logger.warning("互斥锁异常，存在独立数据库护栏，降级放行 key=%s: %s",
                       key, e)
        return _DEGRADED_LOCK_TOKEN


async def redis_release_lock(redis_client, key: str, token: str = "") -> None:
    """释放互斥锁：只删自己加的那把。失败不影响主流程（TTL 到期后会自行回收）。

    原实现无条件 DELETE：当持锁方的执行时间超过 TTL（支付平台退款接口慢、
    进程被 GC/网络卡住），锁会自动过期并被下一个请求抢到，此时前一个请求的
    finally 里这记 DELETE 删掉的是**别人**的锁，第三个请求随即也能进来——互斥彻底失效。
    这不再是理论问题：api/admin.py 的管理员兜底退款在订单已是 refund_pending 时
    不做数据库 CAS（同值 UPDATE 在 MySQL 下 affected_rows 恒为 0），这把 Redis 锁
    是该分支唯一的并发护栏，误删即等于两个管理员各向支付平台发起一笔真实退款。"""
    if not token or token == _DEGRADED_LOCK_TOKEN:
        return
    try:
        await redis_client.eval(_LUA_RELEASE_LOCK, 1, key, token)
    except Exception as e:
        logger.warning(f"互斥锁释放异常 key={key}: {e}")


async def redis_acquire_lock_fresh(db, redis_client, key: str, ttl_seconds: int,
                                   fail_closed: bool | None = None) -> str:
    """抢互斥锁，抢到后立即结束当前事务以丢弃陈旧读快照；未抢到返回空串。

    为什么必须「换快照」：生产 MySQL 默认 REPEATABLE-READ，一致性读走的是「本事务第一次
    读取时建立的快照」。调用方在抢锁之前通常已经做过多次 SELECT（鉴权、权益、会员态），
    该快照早于并发对手提交写入的时刻——于是「先抢锁、再计数」里的计数读到的仍是拿锁前的
    旧值，互斥对本类「计数后判定」的逻辑（会员额度）等于没加，额度仍被并发整倍穿透。
    commit 结束旧事务后，后续读取才会重新取快照，看到对手在持锁期间提交的数据。

    仅用于「先抢锁 → 再计数/查重 → 再写入」的临界区。SQLite 单机串行写不存在该窗口，
    commit 在无活动事务时也是安全的空操作。"""
    token = await redis_acquire_lock(
        redis_client, key, ttl_seconds, fail_closed=fail_closed)
    if not token:
        return ""
    await db.commit()
    return token


async def redis_release_lock_committed(db, redis_client, key: str, token: str) -> None:
    """先提交再释放互斥锁。锁的语义是「临界区内的写入对下一个持锁者可见」：
    get_db 要到响应生成之后才提交，若先释放锁，下一个请求会在「锁已放、数据未落」的窗口里
    读到旧计数，额度/去重判定随之穿透。提交失败只回滚本事务，不吞掉调用方的异常语义。"""
    try:
        await db.commit()
    except Exception as e:
        logger.warning(f"临界区提交失败，已回滚 key={key}: {e}")
        await db.rollback()
    await redis_release_lock(redis_client, key, token)


def to_money(value) -> Decimal:
    """统一金额转 Decimal，避免 float 精度问题"""
    if value is None:
        return Decimal("0")
    if isinstance(value, Decimal):
        return value
    return Decimal(str(value)).quantize(Decimal("0.01"))


def mask_account(channel: str, account: str) -> str:
    """收款账号脱敏（展示层）"""
    if not account:
        return ""
    account = str(account)
    if channel == "alipay" and "@" in account:  # 邮箱
        name, _, domain = account.partition("@")
        return (name[:2] + "***" + "@" + domain) if len(name) > 2 else "***@" + domain
    if len(account) <= 4:
        return account[0] + "***"
    return account[:2] + "****" + account[-4:]
