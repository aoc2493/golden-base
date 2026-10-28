# Contributing

欢迎提交 Issue 与 Pull Request。

## 开发流程

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt -r requirements-dev.txt
pytest
```

提交前请确认：

- `pytest` 全绿，**且 SQLite 与 MySQL 两种方言都跑过**（见下）
- 没有提交 `.env`、证书、密钥或本地数据库
- 新增业务逻辑放在 `app/plugins/<name>/`，不要往 `app/core/` 里加业务词
- 涉及支付 / 权益 / 退款的改动，补一条可复现的测试

## CI 与两种数据库方言

CI 有三个作业，任何一个红都不能合并：

| 作业 | 跑什么 |
| --- | --- |
| 静态检查 / 测试 | `ruff check app tests` + `pytest`（默认 SQLite 内存库）+ `pip-audit` |
| 测试 / MySQL | 同一个 `pytest`，但作业环境变量 `DB_TYPE=mysql`，打真实 MySQL 8 服务 |
| 密钥扫描 | `gitleaks` 扫全历史 |

因为第二个作业换了方言，写测试时有两条硬规则：

1. **建引擎必须跟着 `settings.DB_TYPE` 走**，照抄 `tests/conftest.py::_make_engine`，
   不要在用例里硬写 `create_async_engine("sqlite+aiosqlite:///...")`。
   本地 SQLite 全绿不代表 MySQL 作业绿——反过来也一样。
2. **主键统一用 `BigInteger`**，SQLite 侧由 `app/core/database.py` 的方言补丁编译成
   `INTEGER`（SQLite 只有 `INTEGER PRIMARY KEY` 才是 rowid 别名、才会自增）。
   补丁注册在 sqlite 方言上、无条件生效，因此新表不需要再做特判；
   但如果你在别处手工建过 SQLite 引擎（脚本或临时库），请确认它导入了 `app.core.database`。

改完至少本地跑两遍：

```bash
pytest                              # SQLite
DB_TYPE=mysql pytest                # 需要一台可连的 MySQL，或直接用 CI
```

真实教训：MySQL 作业曾在 `NOT NULL constraint failed: users.id` 上翻红，
原因就是用例里硬编码了 SQLite 引擎，本地永远看不到那个分支。

## 提交信息

使用 Conventional Commits 风格的简短标题，例如：

```
feat(plugin): add quota check to demo capability
fix(payment): reject callback with mismatched amount
docs: clarify PAYMENT_MOCK scope
```

## 代码约定

- core 零业务词：能力码、SKU、价格、文案不写死在 `app/core/`
- 价格只信后端：前端只传「买什么」，不传金额
- 不做破坏式改动时优先保持接口与表结构兼容
- 注释只解释「为什么」，不复述代码在做什么

## 安全

见 [SECURITY.md](SECURITY.md)。安全问题请走私密报告渠道。
