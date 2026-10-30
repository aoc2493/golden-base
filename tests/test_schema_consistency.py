"""init.sql 与 ORM 模型必须描述同一套表与同一套列。

Docker 部署用 sql/init.sql 建表（仅数据卷为空时执行），测试与 SQLite 本地开发用
Base.metadata.create_all。两者一旦漂移，生产表结构与代码就不一致，且只在首次部署
时暴露。这里加两道静态门禁：表名集合、每张表的列名集合都必须完全相同。

只比表名的旧版本可能遗漏：users 表缺 email/password_hash 两列，
表名对得上、测试全绿，直到用户点「邮箱注册」才 500。列级比对才能拦住这类漂移。
"""
import pathlib
import re

from sqlalchemy import UniqueConstraint

from app.core.models import Base

_INIT_SQL = pathlib.Path(__file__).resolve().parents[1] / "sql" / "init.sql"
_CREATE_TABLE = re.compile(r"CREATE TABLE IF NOT EXISTS `?([A-Za-z0-9_]+)`?", re.IGNORECASE)
_CREATE_TABLE_BLOCK = re.compile(
    r"CREATE TABLE IF NOT EXISTS `?([A-Za-z0-9_]+)`?\s*\((.*?)\n\)", re.IGNORECASE | re.DOTALL)
# 行首反引号包裹的名字既可能是列，也可能是索引/约束；后者按首关键字排除。
_INDEX_KEYWORDS = {"PRIMARY", "UNIQUE", "KEY", "INDEX", "CONSTRAINT", "FULLTEXT", "FOREIGN", "SPATIAL"}
_INDEX_LINE = re.compile(
    r"^\s*(?:UNIQUE\s+|FULLTEXT\s+|SPATIAL\s+)?(?:KEY|INDEX)\s+`([A-Za-z0-9_]+)`\s*\(([^)]*)\)",
    re.IGNORECASE | re.MULTILINE)


def _sql_tables() -> set[str]:
    return {m.group(1) for m in _CREATE_TABLE.finditer(_INIT_SQL.read_text(encoding="utf-8"))}


def _sql_columns() -> dict[str, set[str]]:
    """解析 init.sql：表名 -> 列名集合（跳过 KEY/UNIQUE/INDEX/CONSTRAINT 等定义行）。"""
    text = _INIT_SQL.read_text(encoding="utf-8")
    tables: dict[str, set[str]] = {}
    for m in _CREATE_TABLE_BLOCK.finditer(text):
        table, body = m.group(1), m.group(2)
        cols: set[str] = set()
        for line in body.splitlines():
            s = line.strip()
            if not s.startswith("`"):
                continue
            name = s.split("`")[1]
            rest = s[len(name) + 2:].lstrip()
            first = rest.split(None, 1)[0].upper() if rest else ""
            if first in _INDEX_KEYWORDS:
                continue
            cols.add(name)
        tables[table] = cols
    return tables


def test_init_sql_matches_models():
    sql_tables = _sql_tables()
    model_tables = set(Base.metadata.tables)

    assert sql_tables, "sql/init.sql 里没有解析到任何 CREATE TABLE"
    assert model_tables - sql_tables == set(), f"模型有、init.sql 缺: {sorted(model_tables - sql_tables)}"
    assert sql_tables - model_tables == set(), f"init.sql 有、模型缺: {sorted(sql_tables - model_tables)}"


def test_init_sql_columns_match_models():
    sql_cols = _sql_columns()
    assert sql_cols, "sql/init.sql 里没有解析到任何列定义"

    problems = []
    for table_name, table in Base.metadata.tables.items():
        model_cols = {c.name for c in table.columns}
        declared = sql_cols.get(table_name)
        if declared is None:      # 表缺失已由上一个用例覆盖
            continue
        missing = sorted(model_cols - declared)
        extra = sorted(declared - model_cols)
        if missing:
            problems.append(f"{table_name} 缺列（模型有、init.sql 无）: {missing}")
        if extra:
            problems.append(f"{table_name} 多列（init.sql 有、模型无）: {extra}")
    assert not problems, "init.sql 与 ORM 列不一致：\n" + "\n".join(problems)


def _sql_indexes() -> dict[str, list[tuple[str, list[str]]]]:
    """解析 init.sql：表名 -> [(索引名, [列名...])]，含 PRIMARY KEY。"""
    text = _INIT_SQL.read_text(encoding="utf-8")
    out: dict[str, list[tuple[str, list[str]]]] = {}
    for m in _CREATE_TABLE_BLOCK.finditer(text):
        table, body = m.group(1), m.group(2)
        entries: list[tuple[str, list[str]]] = []
        for line in body.splitlines():
            idx = _INDEX_LINE.match(line)
            if idx:
                raw = idx.group(2)
            elif line.strip().upper().startswith("PRIMARY KEY"):
                raw = line.strip()[len("PRIMARY KEY"):]
            else:
                continue
            cols = []
            for part in raw.strip().strip("()").split(","):
                name = part.strip().strip("`").split("(")[0].strip().strip("`")
                if name:
                    cols.append(name.lower())
            entries.append((idx.group(1) if idx else "primary", cols))
        out[table] = entries
    return out


def test_init_sql_indexes_cover_models():
    """ORM 声明的索引/唯一约束必须在 init.sql 里有对应物。

    只按「覆盖列」比对而不是按索引名：init.sql 用 uk_user/uk_code 这类业务命名，
    ORM 里 Column(unique=True, index=True) 生成的是 ix_ 前缀名，名字不同但作用等价；
    反之 ORM 声明了索引而建表脚本没有，就是生产环境缺索引（全表扫描）。
    """
    sql_idx = _sql_indexes()
    assert sql_idx, "sql/init.sql 里没有解析到任何索引定义"

    problems = []
    for table_name, table in Base.metadata.tables.items():
        entries = sql_idx.get(table_name, [])
        first_cols = {cols[0] for _, cols in entries if cols}
        names = {name.lower() for name, _ in entries}
        for col in table.columns:
            if col.index and not col.unique and col.name.lower() not in first_cols:
                problems.append(f"{table_name}.{col.name} 在 ORM 里 index=True，但 init.sql 无索引")
        for idx in table.indexes:
            cols = [c.name.lower() for c in idx.columns]
            if cols and cols[0] not in first_cols:
                problems.append(f"{table_name} 的索引 {idx.name}{cols} 在 init.sql 中缺失")
        for con in table.constraints:
            if isinstance(con, UniqueConstraint) and con.name and con.name.lower() not in names:
                problems.append(f"{table_name} 的唯一约束 {con.name} 在 init.sql 中缺失")
    assert not problems, "init.sql 索引与 ORM 不一致：\n" + "\n".join(problems)


def test_bigint_sqlite_patch_is_not_gated_on_main_db(tmp_path):
    """主库配成 MySQL 时，同进程临时建起的 SQLite 库也必须能自增插入。

    BigInteger→INTEGER 的 SQLite 方言补丁会依据模块导入时的主库类型决定是否注册。
    若仅在主库为 SQLite 时注册，MySQL 作业中新建的 SQLite 文件库会得到
    `id BIGINT NOT NULL PRIMARY KEY`；SQLite 只有 INTEGER 主键才是 rowid 别名，
    插入时会出现 `NOT NULL constraint failed: users.id`。

    必须在子进程里测：补丁是否在「导入 app.core.database 时」注册，取决于那一刻的
    settings.DB_TYPE；在本进程里 monkeypatch 已经太晚（模块早就导入了），
    改出来的用例只会在两种实现下都绿，等于没断言。
    """
    import os
    import subprocess
    import sys

    db_path = (tmp_path / "mysqlmain.db").as_posix()
    script = f"""
import asyncio, sys
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
import app.core.database  # noqa: F401  按 DB_TYPE=mysql 导入，触发被测分支
from app.core.models import Base, User

async def main():
    engine = create_async_engine("sqlite+aiosqlite:///{db_path}")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        ddl = (await conn.execute(text(
            "SELECT sql FROM sqlite_master WHERE name='users'"))).scalar_one()
    async with engine.begin() as conn:
        await conn.execute(User.__table__.insert().values(nickname="测试用户"))
        row = (await conn.execute(text("SELECT id FROM users"))).scalar_one()
    await engine.dispose()
    if "BIGINT" in ddl.upper():
        print("BADDDL:" + ddl, file=sys.stderr)
        sys.exit(3)
    if not row:
        print("BADID:" + repr(row), file=sys.stderr)
        sys.exit(4)
    print("OK")

asyncio.run(main())
"""
    env = {**os.environ,
           "PYTHONIOENCODING": "utf-8",
           "DB_TYPE": "mysql", "DB_HOST": "127.0.0.1", "DB_PORT": "3306",
           "DB_NAME": "app_db", "DB_USER": "ci-user", "DB_PASSWORD": "ci-password",
           "APP_ENV": "development",
           "JWT_SECRET_KEY": os.environ.get("JWT_SECRET_KEY", "test-jwt-secret-" + "0" * 32),
           "ADMIN_TOKEN": os.environ.get("ADMIN_TOKEN", "test-admin-token"),
           "SENSITIVE_FIELD_KEY": os.environ.get("SENSITIVE_FIELD_KEY",
                                                 "test-sensitive-field-key-0123456789")}
    root = str(pathlib.Path(__file__).resolve().parents[1])
    r = subprocess.run([sys.executable, "-c", script], cwd=root, env=env,
                       capture_output=True, text=True, encoding="utf-8", errors="replace",
                       timeout=120)
    assert r.returncode == 0, (
        "主库为 MySQL 时 SQLite 建表/自增失败（BigInteger→INTEGER 方言补丁被按主库配置关掉了）\n"
        f"rc={r.returncode}\nstdout={r.stdout}\nstderr={r.stderr}")
