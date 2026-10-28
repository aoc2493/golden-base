"""init.sql 与 ORM 模型必须描述同一套表。

Docker 部署用 sql/init.sql 建表（仅数据卷为空时执行），测试与 SQLite 本地开发用
Base.metadata.create_all。两者一旦漂移，生产表结构与代码就不一致，且只在首次部署
时暴露。这里加一道静态门禁：表名集合必须完全相同。
"""
import pathlib
import re

from app.core.models import Base

_INIT_SQL = pathlib.Path(__file__).resolve().parents[1] / "sql" / "init.sql"
_CREATE_TABLE = re.compile(r"CREATE TABLE IF NOT EXISTS `?([A-Za-z0-9_]+)`?", re.IGNORECASE)


def _sql_tables() -> set[str]:
    return {m.group(1) for m in _CREATE_TABLE.finditer(_INIT_SQL.read_text(encoding="utf-8"))}


def test_init_sql_matches_models():
    sql_tables = _sql_tables()
    model_tables = set(Base.metadata.tables)

    assert sql_tables, "sql/init.sql 里没有解析到任何 CREATE TABLE"
    assert model_tables - sql_tables == set(), f"模型有、init.sql 缺: {sorted(model_tables - sql_tables)}"
    assert sql_tables - model_tables == set(), f"init.sql 有、模型缺: {sorted(sql_tables - model_tables)}"
