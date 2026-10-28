"""测试基础设施：默认用 SQLite 内存库，`DB_TYPE=mysql` 时打真实 MySQL（CI 的 test-mysql 作业）。

三个关键点：
1. 环境变量必须在导入 app.config 之前设置——settings 在模块导入时就读取完成，
   之后再改无效（会仍按 mysql 去连库）。
2. 必须导入 app.core.database，它注册了 SQLite 方言补丁（BigInteger→INTEGER 等），
   否则 models 里的 BigInteger 主键在 SQLite 下无法自增。
3. `client` 默认带 `Origin`（与 base_url 同源）：CSRF 中间件要求 Cookie 会话的
   状态变更请求证明来自本站，浏览器真实请求也总会带这个头。

`db` 与 `client` 是两个互不相通的库（各自 create_async_engine + 内存/独立连接）：
同一个用例里同时用它们时，`db` 永远看不到 `client` 写入的行——想验证「有没有建号/建单」，
在 client 用例里请判响应本身（如 set-cookie、返回码），别拿 db 计数，那样断言恒真。
"""
import os

os.environ.setdefault("DB_TYPE", "sqlite")
os.environ.setdefault("SQLITE_PATH", ":memory:")
# 测试用的最小安全配置：真实值必须由 .env 提供，这里只为让导入期自检与 JWT 签发可运行
os.environ.setdefault("APP_ENV", "development")
os.environ.setdefault("JWT_SECRET_KEY", "test-jwt-secret-" + "0" * 32)
os.environ.setdefault("ADMIN_TOKEN", "test-admin-token")
os.environ.setdefault("SENSITIVE_FIELD_KEY", "test-sensitive-field-key-0123456789")
os.environ.setdefault("PAYMENT_MOCK", "true")
# 测试环境没有 Redis：限流/黑名单降级放行，避免走 fail-closed 把请求全拦掉
os.environ.setdefault("REDIS_FAIL_CLOSED", "false")
os.environ.setdefault("REDIS_SOCKET_TIMEOUT", "0.2")

import httpx
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

import app.core.database  # noqa: F401  副作用导入：注册 SQLite 方言补丁
from app.config import settings
from app.core.models import Base


def _make_engine():
    if settings.DB_TYPE == "mysql":
        # MySQL 不共享 StaticPool：每次连接都是真实连接，并发回调测试才走得到行锁
        return create_async_engine(settings.database_url, pool_pre_ping=True,
                                   pool_size=5, max_overflow=5)
    # StaticPool：让所有连接复用同一个内存库，否则每次取连接都是一个全新的空库
    return create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )


async def _reset_schema(engine):
    async with engine.begin() as conn:
        if settings.DB_TYPE == "mysql":
            # MySQL 库在 CI 里是多作业共享的容器：每次从干净 schema 起步，
            # 否则上一个用例的种子/订单会被读到（SQLite 内存库天然没有这个问题）。
            await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)


@pytest_asyncio.fixture
async def db():
    engine = _make_engine()
    await _reset_schema(engine)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        yield session
    await engine.dispose()


@pytest_asyncio.fixture
async def client():
    """ASGI 客户端 + 已种入 demo 商品的独立库。"""
    from app.core.database import get_db
    from app.main import app
    from app.plugins import registry

    engine = _make_engine()
    await _reset_schema(engine)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    # 插件商品种子（正式启动时由 main._seed_base_data 调用同一钩子）
    async with factory() as session:
        await registry.get("demo").service.seed_data(session)
        await session.commit()

    async def _override_db():
        async with factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    app.dependency_overrides[get_db] = _override_db
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test",
                                 headers={"Origin": "http://test"}) as c:
        yield c
    app.dependency_overrides.clear()
    await engine.dispose()
