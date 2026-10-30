# Golden Base

FastAPI + H5 通用应用底座：登录、支付、会员、卡券、分销、权益核销、结果缓存、
后台管理、部署基线全部内置，业务能力以插件形式接入。

> **core 不含业务逻辑**：`app/core/` 里没有垂直业务的规则与内容生成逻辑，业务能力经
> `app/plugins/<your-biz>/` 的 manifest + 钩子接入，新增业务不必改 core 与 `main.py`。
> 已知例外（可审计）：会员规则、合规告知等中文文案在 core 里给了默认值，
> 正式业务应经 `system_configs`（membership_rules / distribution_rules）按键覆盖，
> 而不是改 core 源码。
> 仓库自带 `app/plugins/demo/` 作为最小示例，跑通「登录 → 下单 → 支付 → 权益 → 调用」全链路。

## 特性

- **下单型计费**：一份内容一次；会员周期额度模型（总池 + 单工具单日上限）已内置统计与判定
- **一个权益账户**：会员到期、单次权益、卡券、时长卡统一记账
- **真实支付接入**：微信支付 V3（H5/JSAPI）、支付宝手机网站支付，回调验签 + 幂等 + CAS 原子履约
- **分销合规**：一级直推、等级晋升、月度阶梯、提现审核与敏感词检测
- **通用后台**：订单/退款/会员/用户/佣金/提现/发票/对账/告警
- **安全默认**：fail-closed 启动自检、JWT httpOnly Cookie、CSRF、敏感字段加密、限流、审计日志
- **真实身份**：生产邮箱验证码注册、持久化密码重置工单、按账号登录失败限流
- **并发资金安全**：pending 订单数据库唯一意图键、渠道调用前持久化退款单号
- **一条命令部署**：`docker compose up --build` 起 MySQL + Redis + 后端 + nginx

## 能力接线状态

| 状态 | 能力 |
|---|---|
| 开箱已接线 | 邮箱/设备/微信登录、支付回调、订单履约、退款、会员、权益、卡券、发票、对账、告警 |
| 由业务插件接入 | 运行期限额 `quota.charge_member_view`、报告生成、业务收藏/注销清理 |
| 需业务明确开启 | 支付前免责勾选、佣金个税代扣 |

上线清单必须按业务法域逐项确认。

## 快速开始（Docker）

```bash
cp .env.example .env
# 修改 .env 里的 JWT_SECRET_KEY / ADMIN_TOKEN / SENSITIVE_FIELD_KEY / DB_PASSWORD / REDIS_PASSWORD
docker compose up --build -d
```

`DB_PASSWORD` 同时用于应用连库与 MySQL 容器的账号口令，.env 里不需要也不应再写
`MYSQL_PASSWORD`。示例文件里的 `dev-*` 口令只在开发环境可用，`APP_ENV=production`
时启动自检会按值阻断。

打开 <http://localhost:8080>，按页面提示：

1. 注册 / 登录（非生产环境跳过邮箱验证码）
2. 加载商品清单
3. 输入一段文本 → **Buy & pay**（`PAYMENT_MOCK=true` 时走模拟支付）
4. **Call demo API** 验证权益已解锁

> `PAYMENT_MOCK` 只允许在非生产环境开启；`APP_ENV=production` 时启动自检直接拒绝，
> `/api/payment/mock/pay` 也会返回 403。

## 本地开发（无 Docker）

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt -r requirements-dev.txt
cp .env.example .env
```

把 `.env` 改成 SQLite 轻量模式：

```dotenv
APP_ENV=development
DB_TYPE=sqlite
SQLITE_PATH=./app.db
WEB_ROOT=./web
PAYMENT_MOCK=true
# 本机没有 Redis 时必须关闭 fail-closed，否则限流/黑名单会把请求全拦掉
REDIS_FAIL_CLOSED=false
```

启动：

```bash
uvicorn app.main:app --reload
```

- 页面：<http://127.0.0.1:8000>
- 接口文档（仅非生产）：<http://127.0.0.1:8000/docs>
- 健康检查：`GET /health`

## 测试

```bash
pytest
```

测试用内存 SQLite（并发抢占那几个用例用临时文件库，因为内存库的 StaticPool 只有一条连接，
测不出「提交后才可见」），不依赖 MySQL / Redis / 支付凭据。按链路分工：`test_demo_flow` 走完整
购买链路与越权保护；`test_membership_fulfillment` 锁会员权益顺延；`test_payment_idempotent`、
`test_refund_state`、`test_concurrent_claims` 验重复回调下的抢占语义（履约权与退款权都靠带条件的
原子 UPDATE 抢，抢不到就幂等返回）；`test_invoice_guard` 钉住开票资格判据与退款联动（已退款不开票、
一单一票靠唯一约束而不是先查后插）；`test_crypto_field` 验敏感字段加解密往返、篡改与换密钥
的失败口径，并断言「最坏长度的姓名/账号加密后仍放得进列宽」；`test_reconcile` 覆盖渠道账单解析与
七类对账差错的判定方向（金额不符一律不自动履约、掉单才走回调同源入口补发且补发后仍留痕）；
`test_guards_wired` 检查「文档里承诺的安全开关确实接在代码上」；
`test_startup_guard` 覆盖生产启动自检（含 Redis 连通性门禁）；`test_schema_consistency` 逐表逐列比对
`sql/init.sql` 与 ORM（含索引覆盖）；`test_security_hardening` 锁住请求头注入、图片地址白名单、
CSRF 来源判定等安全边界。

存量库升级不要重跑 `init.sql`，按顺序执行 `sql/migrations/*.sql`（幂等）；非默认库名时，
请先创建并选择目标数据库后执行 `init.sql`（脚本不再写死 `app_db`）；后端启动时
还会核对一次表结构，生产环境缺表/缺列会直接拒绝启动并指名缺什么。

CI（`.github/workflows/ci.yml`）全部阻断合并：Ruff、带 40% 覆盖率下限的 Pytest、
新增/资金关键模块 Mypy、pip-audit、MySQL 回归和 gitleaks 全历史密钥扫描。
升级依赖前先本地跑一遍 `pip-audit`，带已知 CVE 的版本不要提交。

## 目录结构

```
app/
├─ main.py                 # 入口：挂 core 路由 + 自动发现插件路由
├─ config.py               # 全部配置项（真值走环境变量）
├─ core/                   # 底盘：不含垂直业务逻辑
│  ├─ plugin_contract.py   # 插件契约：Capability / 钩子
│  ├─ api/                 # auth user order payment membership entitlement ...
│  ├─ services/            # 会员 / 权益 / 履约 / 分销 / 发票 / 卡券
│  ├─ tasks/               # 定时任务：关单 / 对账 / 退款重试
│  └─ utils/               # 支付、加解密、告警、AI 标识
└─ plugins/
   ├─ __init__.py          # 注册表：扫描插件包、聚合能力
   └─ demo/                # 示例插件（可整目录复制为新业务）
      ├─ manifest.py       # 能力码 / SKU / 价格
      ├─ service.py        # 下单快照、支付后交付、种子数据
      └─ router.py         # 业务接口
web/                       # 最小演示前端（纯静态）
nginx/ Dockerfile docker-compose.yml
sql/init.sql               # 全量建表（仅空数据卷首启执行）
sql/migrations/            # 存量库增量脚本（幂等，按编号执行）
```

## 写一个业务插件

见 [docs/plugin.md](docs/plugin.md)。最小步骤：

1. 复制 `app/plugins/demo/` 为 `app/plugins/<your-biz>/`
2. 改 `manifest.py`：能力码、SKU、价格（分）
3. 改 `service.py`：`prepare_order` / `on_paid`，按需实现 `on_refund` 等钩子
4. 改 `router.py`：业务接口，用 `check_feature` 做权益门禁
5. 重启即自动注册；商品行由 `seed_data(db)` 写入

## 部署与安全

- 部署基线、证书、反向代理、备份与上线核对：[docs/deploy.md](docs/deploy.md)
- 安全模型与漏洞报告方式：[SECURITY.md](SECURITY.md)
- 依赖版本说明：[docs/dependency-notes.md](docs/dependency-notes.md)

## License

项目代码采用 [MIT](LICENSE)，第三方组件许可见
[`THIRD_PARTY_LICENSES.md`](THIRD_PARTY_LICENSES.md)。
