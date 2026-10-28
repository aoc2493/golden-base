# Golden Base

FastAPI + H5 通用应用底座：登录、支付、会员、卡券、分销、权益核销、结果缓存、
后台管理、部署基线全部内置，业务能力以插件形式接入。

> **core 零业务词**：`app/core/` 不认识任何具体业务；新增业务 = 新增
> `app/plugins/<your-biz>/` 一个目录，core 与 `main.py` 一行不改。
> 仓库自带 `app/plugins/demo/` 作为最小示例，跑通「登录 → 下单 → 支付 → 权益 → 调用」全链路。

## 特性

- **两种计费模型**：下单型（一份内容一次）/ 运行期扣额（每次调用）
- **一个权益账户**：会员到期、单次权益、卡券、时长卡统一记账
- **真实支付接入**：微信支付 V3（H5/JSAPI）、支付宝手机网站支付，回调验签 + 幂等 + CAS 原子履约
- **分销合规**：一级直推、等级晋升、月度阶梯、提现审核、敏感词与推广资格考试
- **通用后台**：订单/退款/会员/用户/佣金/提现/发票/对账/告警
- **安全默认**：fail-closed 启动自检、JWT httpOnly Cookie、CSRF、敏感字段加密、限流、审计日志
- **一条命令部署**：`docker compose up --build` 起 MySQL + Redis + 后端 + nginx

## 快速开始（Docker）

```bash
cp .env.example .env
# 修改 .env 里的 JWT_SECRET_KEY / ADMIN_TOKEN / SENSITIVE_FIELD_KEY / 数据库与 Redis 密码
docker compose up --build -d
```

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

测试用内存 SQLite，不依赖 MySQL / Redis / 支付凭据。`tests/test_demo_flow.py`
覆盖完整购买链路与越权保护。

CI（`.github/workflows/ci.yml`）四道门禁全部阻断合并：`ruff check .`、
`pytest`、`pip-audit -r requirements.txt`、gitleaks 全历史密钥扫描。
升级依赖前先本地跑一遍 `pip-audit`，带已知 CVE 的版本不要提交。

## 目录结构

```
app/
├─ main.py                 # 入口：挂 core 路由 + 自动发现插件路由
├─ config.py               # 全部配置项（真值走环境变量）
├─ core/                   # 底盘：零业务词
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
nginx/ Dockerfile docker-compose.yml sql/init.sql
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

[MIT](LICENSE)
