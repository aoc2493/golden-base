# Security Policy

## 报告漏洞

请**不要**在公开 Issue 中披露安全问题。请通过 GitHub Security Advisories
（仓库页 → Security → Report a vulnerability）私下报告，并附上：

- 影响版本 / commit
- 复现步骤与最小样本
- 影响面评估（越权、资金、数据泄露等）

我们会在 72 小时内确认，并在修复发布后致谢（如你愿意署名）。

## 安全默认

本项目按「默认安全、失败即拒绝」设计：

- 启动自检 fail-closed：`JWT_SECRET_KEY`、`ADMIN_TOKEN`、`SENSITIVE_FIELD_KEY`
  缺失、过短或仍是 `.env.example` 的示例值时拒绝启动；生产环境额外校验 CORS、
  管理二次密码，并逐值拦下 `DB_PASSWORD` / `REDIS_PASSWORD` 的示例口令。
  AI 生成内容标识（`utils/ai_mark.py` + `AI_MARK_*`）是给业务插件接入的能力：底座自身
  不生成内容，故未配置时只作最高级告警而不阻断（不含 AI 合成内容的部署没有标识义务）。
- 启动期结构校验：`information_schema` 与 ORM 逐表逐列比对，生产环境缺列直接拒绝启动
  （避免「服务起来了、用户一点就 500」）；存量库修复走 `sql/migrations/`。
- `PAYMENT_MOCK=true` 仅允许非生产环境；生产环境启动即拒绝，接口本身也返回 403。
- 支付回调：验签（微信 APIv3 平台证书/公钥 + 5 分钟时间戳窗口；支付宝 RSA2）+
  金额校验 + 幂等 + CAS 原子履约，防止重放与并发超发。
- 会话：JWT 算法白名单、校验 aud/iss，httpOnly Cookie；登出/禁用经 jti 黑名单即时失效。
- 状态变更请求的 CSRF 防护：`/api/*` 要求同源 Origin（或 Bearer 令牌、或支付平台回调），
  其他路径走双提交 Cookie。**不依赖 Cookie 的 SameSite 兜底**——把
  `AUTH_COOKIE_SAMESITE` 设为 `none`（跨域部署）时防护依然有效。
- 资源归属：所有订单/权益/报告类接口按 `user_id` 过滤，越权访问一律按「不存在」返回。
- 敏感字段（收款账号、实名）落库加密；`SENSITIVE_FIELD_KEY` 一旦丢失，已加密数据不可恢复。
- 上传：content-type 白名单 + 文件头魔数 + 流式体积上限 + 像素上限；全局请求体上限 8MB。
- 限流、管理端 IP 白名单、管理令牌爆破锁定、审计日志均内置于 core；
  Redis 故障时的降级方向由 `REDIS_FAIL_CLOSED` 决定（默认拦截）。
- 响应头与地址类入参：`X-Request-ID` 只接受 `[A-Za-z0-9._-]{1,64}`，其余一律重新生成
  （防止反射注入与日志投毒）；头像/反馈图地址只接受站内相对路径或配置的 COS/CDN 域名；
  推广触达上报（公开端点）按 IP 限流，非法邀请码不落库。

## 插件的信任边界

插件是与 core **同进程、同权限**的 Python 包：持有数据库会话、可读 `settings` 中的
支付密钥与 `SENSITIVE_FIELD_KEY`、可注册任意路由。底座只做能力登记与权益核销，
**不提供沙箱**，也无法提供（Python 进程内隔离挡不住同进程代码）。

因此：只安装经过审计的插件代码，把 `app/plugins/` 视为与 `app/core/` 同级的可信代码；
第三方插件上线前必须走代码评审，不要把「插件」当成安全隔离层。

## 已知残余风险

- 访问令牌有效期默认 7 天（`JWT_EXPIRE_DAYS`），无刷新令牌机制；缩短有效期需自行接入
  刷新流程。登出即时失效依赖 Redis 黑名单：未配置 Redis（SQLite 轻量模式）时，
  令牌在自然过期前始终有效。
- 限流、登出黑名单、设备码释放标记、会员额度互斥锁四类控制全部存在 Redis 上，因此它们的
  可用性等于 Redis 的可用性。`REDIS_FAIL_CLOSED=true`（默认）时 Redis 不可达直接拒绝请求，
  是拿可用性换确定性；改成 `false` 则这四项在故障窗口内一律放行——攻击者可以无限次枚举设备码，
  已注销的令牌也能继续用。生产环境启动自检会先 `PING` Redis，连不上就拒绝启动并 CRITICAL 告警；
  但如果生产配置显式写了 `REDIS_FAIL_CLOSED=false`，启动自检只给建议、不阻断，这个降级窗口
  是否可接受要由部署方确认（`test_startup_guard` 把两种行为都钉住了）。
- 支付回放不另建 nonce 表：微信侧有 5 分钟时间戳窗口，且重复回调经 CAS 幂等处理，
  不会二次履约；如需更严的报文级去重，应在网关层加 nonce 缓存。
- `docker-compose.yml` 的镜像标签是可覆盖的次版本标签（`mysql:8.0` 等），不是 digest。
  强可复现性要求下，请把 `MYSQL_IMAGE` / `REDIS_IMAGE` / `NGINX_IMAGE` / `PYTHON_IMAGE`
  固定为 `@sha256:` 摘要。
- 设备码登录（`POST /api/auth/login` 传 `device_code`）是长期有效凭证：持码即可登录对应
  账号，没有有效期与二次校验。设备码视同密码保管，不要放进可分享的链接或截图。
- 三项法定义务控制在默认配置下处于关闭状态：年龄门槛（原 A8 成年声明/监护人同意）按属主决策
  于 2026-09-11 关闭、`minor_guard` 恒放行；支付前免责勾选的服务端校验
  `ENFORCE_PAYMENT_DISCLAIMER` 默认关闭；佣金提现代扣个税 `WITHDRAW_TAX_ENABLED` 默认关闭。
  默认关闭都有理由（不阻断开箱即用的演示、重新开启要业务侧先接 UI），但「默认关闭」与
  「没人决定过」在日志里长得一模一样，所以生产环境加了确认闸门：未置
  `COMPLIANCE_DECISIONS_ACK=true` 时启动自检把这三项列为**阻断项**（拒绝启动），
  确认后仍以 ERROR 级逐条留痕。风险并没有因此消失——确认只代表「有人看过」，
  是否要把某项真正打开，仍要按本部署的业务与法域判断（`test_startup_guard` 钉住了两种行为）。

## 部署方责任

- 替换 `.env` 中所有示例密钥，生产必须 `APP_ENV=production`（示例值会被启动自检拦下）。
- 仅通过 HTTPS 对外；MySQL / Redis 不对公网暴露（随附 compose 不发布这两个端口）。
- 定期执行 `pip-audit -r requirements.txt` 并升级依赖（CI 已阻断带已知 CVE 的版本）。
- 妥善离线保管 `SENSITIVE_FIELD_KEY`。
- 如修改 `app/plugins/` 或 `app/core/`，同步跑 `pytest`：CI 会在 SQLite 与 MySQL 8
  两种数据库上执行同一套用例。
