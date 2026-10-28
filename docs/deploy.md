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
由 `tests/test_schema_consistency.py` 守住：表名、每张表的列名、ORM 声明的索引都要对得上，
改模型却漏改 init.sql 会直接让 CI 变红。存量库的增量变更写在 `sql/migrations/`，
后端启动时还会用 `information_schema` 逐表逐列核对一次——缺列在生产环境直接拒绝启动。

面向「拿到底座 → 接入业务 → 上线运营」的部署方。

## 1. 交付内容

| 目录 / 文件 | 说明 |
|---|---|
| `app/core/` | 底盘：登录、支付、会员、卡券、分销、权益、结果缓存、发票、合规、后台、对账、告警 |
| `app/plugins/demo/` | 示例插件；新业务复制该目录改造 |
| `app/config.py` | 全部配置项，真值走环境变量 |
| `sql/init.sql` | 全量建表 + 会员三档种子，仅在 MySQL 数据卷为空时执行 |
| `sql/migrations/` | 存量库增量脚本（按编号顺序执行，幂等，可重复运行） |
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
- `.env.example` 里的 `dev-*` 示例口令（JWT/ADMIN_TOKEN/SENSITIVE_FIELD_KEY/DB_PASSWORD/
  REDIS_PASSWORD）在生产启动时按值阻断，照抄示例文件上不了线。
- 三项法定义务控制默认按「开箱可用」关闭，而生产环境要求有人显式确认过才允许启动：
  先逐项判断本部署的处置，再在 `.env` 写明 `COMPLIANCE_DECISIONS_ACK=true`；
  未确认时启动自检把当前仍关闭的项列为阻断项（拒绝启动），确认后每次启动仍以 ERROR 级
  逐条留痕。可选的处置：
  `ENFORCE_PAYMENT_DISCLAIMER=true`（支付前免责勾选的服务端校验，需前端先接签署 UI）、
  `WITHDRAW_TAX_ENABLED=true`（佣金提现代扣个税，税率见 `WITHDRAW_TAX_RATE`）。
- 年龄门槛（成年声明 / 监护人同意）在本底座里恒放行（`minor_guard` 不做拦截）；
  这条决定不在 `.env` 里（刻意不做成开关：法定义务做成配置项，一次改动就能静默关掉且不留痕），
  重新打开要改 `app/core/services/minor_guard.py` 的 `gate_payer` / `gate_bio`，
  判据（周岁推算、农历换算、留痕）都已实现并有测试。若业务可能触达未成年人，
  需在运营侧另做限制或把门槛打开。

## 3. 部署

```bash
cp .env.example .env   # 填生产值
docker compose up --build -d
```

- 默认对外端口 `HTTP_PORT=8080`；生产建议在前置网关（云 LB / 宿主 nginx / certbot）终结 TLS 后回源。
- MySQL / Redis 不映射宿主端口，只在 compose 内网可达。
- 容器非 root、`cap_drop: ALL`、`no-new-privileges`。
- `backend` 通过 healthcheck 等 MySQL/Redis 真正可连再启动（首次初始化会跑 init.sql，约需数十秒）。
- 生产启动时后端自己也会向 Redis 发一次 `PING`：地址/端口/密码写错时 `redis.from_url` 不会报错
  （惰性建连），要到第一个真实请求才暴露，而限流、token 注销黑名单、会员额度互斥锁全挂在 Redis 上。
  连不上即拒绝启动并发告警，不会带着失效的安全控制面「启动成功」。
- `REDIS_FAIL_CLOSED`（默认 true）决定 Redis 中途不可达时的取舍：true 整体拒绝、false 降级放行。
  置 false 时每次启动都会打一条 ERROR 级自检记录——故障窗口内设备码枚举不限速、已注销 token 仍可用。
- 全新库由 `sql/init.sql` 初始化；已有库不要重复执行它，改用增量脚本：

```bash
for f in sql/migrations/*.sql; do
  docker compose exec -T mysql mysql -u"$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" < "$f"
done
```

  脚本全部按 `information_schema` 判存在性后再执行，可重复运行；执行前先
  `mysqldump --single-transaction` 备份。漏跑不会静默：启动时的结构校验会在生产环境
  直接拒绝启动并指名缺失的表/列。

## 4. 上线核对

- [ ] 仅 nginx / HTTPS 对外；MySQL、Redis 均不暴露公网且有强密码
- [ ] 启动日志无「生产环境 Redis 连不上」——Redis 承载限流/黑名单/额度互斥锁，不可达时服务被刻意拒绝启动
- [ ] 存量库已执行 `sql/migrations/` 下的全部脚本，启动日志无「结构校验」报错
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
