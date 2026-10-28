# 部署与上线核对

## 镜像可复现性

`docker-compose.yml` 的镜像都可以用环境变量覆盖：`MYSQL_IMAGE` / `REDIS_IMAGE` /
`NGINX_IMAGE` / `PYTHON_IMAGE`。默认值是次版本标签（如 `mysql:8.0`），适合快速起步；
要求「同一份配置在任何时间构建出同一镜像」时，把它们改成带摘要的引用：

```bash
MYSQL_IMAGE=mysql:8.0@sha256:<digest>
PYTHON_IMAGE=python:3.12-slim@sha256:<digest>
```

建库走 `sql/init.sql`（仅在数据卷为空时执行），它与 `app/core/models.py` 的一致性
由 `tests/test_schema_consistency.py` 守住——改模型却漏改 init.sql 会直接让 CI 变红。

面向「拿到底座 → 接入业务 → 上线运营」的部署方。

## 1. 交付内容

| 目录 / 文件 | 说明 |
|---|---|
| `app/core/` | 底盘：登录、支付、会员、卡券、分销、权益、结果缓存、发票、合规、后台、对账、告警 |
| `app/plugins/demo/` | 示例插件；新业务复制该目录改造 |
| `app/config.py` | 全部配置项，真值走环境变量 |
| `sql/init.sql` | 全量建表 + 会员三档种子，仅在 MySQL 数据卷为空时执行 |
| `nginx/nginx.conf` | 静态前端 + `/api` 反代 + 限流 + 安全头 |
| `docker-compose.yml` | MySQL + Redis + 后端 + nginx |
| `.env.example` | 环境变量模板，复制为 `.env` 后填真值 |
| `web/` | 最小演示前端，上线前替换为你的前端产物 |

## 2. 生产配置

必须替换的项：

```dotenv
APP_ENV=production
PAYMENT_MOCK=false
CORS_ORIGINS=https://your-domain.com
JWT_SECRET_KEY=<openssl rand -hex 32>
ADMIN_TOKEN=<随机长串>
SENSITIVE_FIELD_KEY=<openssl rand -hex 32>
ADMIN_OPERATE_PASSWORD=<管理端二次密码>
AI_MARK_PROVIDER_NAME=<真实主体名称>
DB_PASSWORD=<强密码>
MYSQL_ROOT_PASSWORD=<强密码>
REDIS_PASSWORD=<强密码>
```

- `SENSITIVE_FIELD_KEY` 一旦上线不得更换：换了之后已入库的密文全部解不开。
- `TRUST_PROXY_HEADERS=true` 时务必同时配置 `PROXY_AUTH_SECRET`，并让 nginx 注入
  `X-Proxy-Auth`（本仓库 `nginx/nginx.conf` 已注入），否则限流与管理端爆破锁定可被伪造头绕过。

## 3. 部署

```bash
cp .env.example .env   # 填生产值
docker compose up --build -d
```

- 默认对外端口 `HTTP_PORT=8080`；生产建议在前置网关（云 LB / 宿主 nginx / certbot）终结 TLS 后回源。
- MySQL / Redis 不映射宿主端口，只在 compose 内网可达。
- 容器非 root、`cap_drop: ALL`、`no-new-privileges`。
- 全新库由 `sql/init.sql` 初始化；已有库不要重复执行。

## 4. 上线核对

- [ ] 仅 nginx / HTTPS 对外；MySQL、Redis 均不暴露公网且有强密码
- [ ] `JWT_SECRET_KEY` / `SENSITIVE_FIELD_KEY` 为 32 字节以上随机值
- [ ] `ADMIN_TOKEN` / `ADMIN_OPERATE_PASSWORD` 已替换，`/docs` 在生产关闭
- [ ] `CORS_ORIGINS` 明确列域名，禁止 `*`
- [ ] `PAYMENT_MOCK=false`（生产开启会被启动自检阻断）
- [ ] 支付回调地址为 HTTPS，且微信/支付宝后台都指向 `/api/payment/*/notify`
- [ ] 上传接口有登录、类型白名单、文件头校验与大小限制
- [ ] 告警通道（`ALERT_WECOM_WEBHOOK` / `ALERT_DINGTALK_WEBHOOK`）已接入
- [ ] 备份策略覆盖 MySQL 数据卷；`SENSITIVE_FIELD_KEY` 有离线备份

## 5. 上线前必测（真实环境，不能用 mock 替代）

- [ ] 真实小额支付 → 回调履约 → 权益解锁，全程不二次付款
- [ ] 回调重放只到账一次；并发回调不超发（真实 MySQL + Redis）
- [ ] 未付费抓包拿不到完整结果；越权访问他人结果被拒
- [ ] 退款链路、会员到期、卡券核销、分销计佣正确
- [ ] 每日对账、掉单主动查单在真实渠道账单下跑通

## 6. 运维

- 定时任务：关单、对账、退款重试、权益过期由 `app/core/tasks/scheduler.py` 驱动。
- 告警：`app/core/utils/alert.py` 将 ERROR 级日志接入企业微信/钉钉，含每日心跳。
- 备份：MySQL 用 `mysqldump --single-transaction`；`.env` 与 `SENSITIVE_FIELD_KEY` 单独离线保存。
