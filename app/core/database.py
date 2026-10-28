from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from app.config import settings

_IS_SQLITE = settings.DB_TYPE == "sqlite"

if _IS_SQLITE:
    # SQLite 下 BIGINT 主键不是 rowid 别名，无法自增；统一编译为 INTEGER 兼容建表。
    # MySQL 方言不受影响，仍按 BIGINT 建表。
    from sqlalchemy import BigInteger as _BigInteger
    from sqlalchemy.ext.compiler import compiles as _compiles

    @_compiles(_BigInteger, "sqlite")
    def _bigint_to_integer(type_, compiler, **kw):
        return "INTEGER"

# SQLite 不支持连接池参数与 FOR UPDATE；生产仍走 MySQL 完整参数。
# SQLite 下另关闭 insertmanyvalues：批量 INSERT+RETURNING 在 aiosqlite 上不可靠，逐条执行更稳。
_engine_kwargs = {"echo": False}
if _IS_SQLITE:
    _engine_kwargs["insertmanyvalues_page_size"] = 1
    # 本地 SQLite 模式：请求会话的事务跨整轮请求（含 Redis 不可达时的秒级超时等待），
    # 默认 5s 忙等待下并发写极易抛 "database is locked"。给 DBAPI 连接 30s 锁等待。
    _engine_kwargs["connect_args"] = {"timeout": 30}
else:
    # pool_pre_ping：每次取连接前先探活，避免拿到已被 MySQL 断开/回收的连接而报错
    # （默认关闭，是长连接池 + 防火墙空闲断连场景下「偶发 500」的常见根因）。
    # pool_timeout：连接池耗尽时最多等 30s 再抛错，而不是无限等待把请求挂死。
    _engine_kwargs.update(pool_size=10, max_overflow=20, pool_recycle=3600,
                         pool_pre_ping=True, pool_timeout=30)

    # ---- aiomysql 适配器兼容补丁（勿删，下方注释说明必要性） ----
    # 现象：连接池 pre_ping 以无参形式调用 connection.ping()，而 SQLAlchemy 的
    # AsyncAdapt_aiomysql_connection.ping 签名为 (self, reconnect)，reconnect 未给默认值，
    # 于是抛 TypeError: ping() missing 1 required positional argument: 'reconnect'。
    # 影响面：「支付查单补偿」「退款主动核实」两个资金定时任务每轮必崩——
    # 掉单不会自动补发、退款状态不会主动核实，属直接资损路径。
    # 处理：为 reconnect 补默认值，保留 pre_ping 探活能力（优于直接关掉 pre_ping）。
    # 上游修复后本补丁自然失效（检测到签名已有默认值则跳过），不会重复包装。
    try:
        from sqlalchemy.dialects.mysql.aiomysql import (
            AsyncAdapt_aiomysql_connection as _AioMySQLConn,
        )

        _orig_ping = _AioMySQLConn.ping
        if "reconnect" in (_orig_ping.__code__.co_varnames or ()):

            def _ping_with_default(self, reconnect=True):
                return _orig_ping(self, reconnect)

            _AioMySQLConn.ping = _ping_with_default
    except Exception:  # 补丁失败不阻断启动：退回无探活，由 pool_recycle 兜底
        pass

engine = create_async_engine(settings.database_url, **_engine_kwargs)

if _IS_SQLITE:
    # 每个底层 DBAPI 连接建立时调优：
    #   journal_mode=WAL：读不阻塞写、写不阻塞读，并发请求不再互相整库锁死；
    #   busy_timeout=30000：与 connect_args.timeout 双保险，遇到锁时最多等 30s 而不是立即报错；
    #   synchronous=NORMAL：WAL 下安全且更快（fsync 频次降低）。
    # 仅影响本地 SQLite 文件，生产 MySQL 路径完全不走这里。
    from sqlalchemy import event as _event

    @_event.listens_for(engine.sync_engine, "connect")
    def _sqlite_pragma(dbapi_conn, _record):
        cur = dbapi_conn.cursor()
        try:
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA busy_timeout=30000")
            cur.execute("PRAGMA synchronous=NORMAL")
        finally:
            cur.close()


def row_lock(stmt):
    """行级锁兼容助手：MySQL 下 SELECT FOR UPDATE；SQLite 无此语法，
    其库级写锁 + 单进程部署已足够互斥，直接返回原语句。"""
    return stmt if _IS_SQLITE else stmt.with_for_update()

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncSession:
    """依赖注入：获取数据库会话"""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
