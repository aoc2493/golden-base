-- ============================================
-- 通用底座 · 数据库初始化脚本（从 app/core/models.py 重新生成，业务无关）
-- 字符集：utf8mb4；全新部署仅需执行本脚本即得到完整结构。
-- 表结构与 ORM 严格一致：列/类型/可空/默认/唯一/索引均取自 models.py 声明。
-- 不含任何垂直业务表与商品；业务由 app/plugins/<你的业务>/ 提供。
-- ============================================
CREATE DATABASE IF NOT EXISTS `app_db` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE `app_db`;

-- ===== 用户表 =====
CREATE TABLE IF NOT EXISTS `users` (
  `id`                  BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `device_code`         VARCHAR(64)  DEFAULT NULL COMMENT '外部浏览器兜底设备码',
  `oa_openid`           VARCHAR(64)  DEFAULT NULL COMMENT '服务号网页授权openid',
  `mp_openid`           VARCHAR(64)  DEFAULT NULL COMMENT '小程序openid',
  `unionid`             VARCHAR(64)  DEFAULT NULL,
  `phone`               VARCHAR(20)  DEFAULT NULL,
  `nickname`            VARCHAR(50)  DEFAULT NULL,
  `avatar_url`          VARCHAR(500) DEFAULT NULL,
  `status`              SMALLINT     DEFAULT 1 COMMENT '1正常 2已注销',
  `declared_birth_date` VARCHAR(20)  DEFAULT NULL COMMENT '自报公历出生日期（年龄门槛）',
  `age_declared_at`     DATETIME     DEFAULT NULL COMMENT '成年声明时点',
  `inviter_id`          BIGINT UNSIGNED DEFAULT NULL COMMENT '一级邀请人，仅绑定一次',
  `invited_at`          DATETIME     DEFAULT NULL,
  `last_login_type`     VARCHAR(16)  DEFAULT NULL COMMENT '最近登录标识类型 device/oa_openid/mp_openid/unionid',
  `last_login_value`    VARCHAR(64)  DEFAULT NULL COMMENT '最近登录标识值',
  `created_at`          DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY `uk_device_code` (`device_code`),
  UNIQUE KEY `uk_oa_openid` (`oa_openid`),
  UNIQUE KEY `uk_mp_openid` (`mp_openid`),
  UNIQUE KEY `uk_unionid` (`unionid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='用户表（JWT无状态，不存token）';

-- ===== 身份台账表（登录标识 ↔ user_id 双向唯一映射）=====
CREATE TABLE IF NOT EXISTS `user_identities` (
  `id`            BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `user_id`       BIGINT UNSIGNED NOT NULL,
  `id_type`       VARCHAR(16)     NOT NULL COMMENT 'device/oa_openid/mp_openid/unionid',
  `id_value`      VARCHAR(64)     NOT NULL,
  `first_seen_at` DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `last_login_at` DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY `uk_identity_value` (`id_type`, `id_value`),
  INDEX `ix_user_identities_user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='身份台账（双向定位存储底座）';

-- ===== 结果缓存表（通用：user_id+cache_key+data+expire）=====
CREATE TABLE IF NOT EXISTS `result_cache` (
  `id`          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `user_id`     BIGINT UNSIGNED NOT NULL,
  `cache_key`   VARCHAR(64)     NOT NULL,
  `input_data`  JSON            NOT NULL,
  `result_data` JSON            NOT NULL,
  `api_source`  VARCHAR(32)     DEFAULT NULL,
  `created_at`  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `expire_at`   DATETIME        NOT NULL,
  INDEX `idx_rc_user_id` (`user_id`, `id`),
  INDEX `idx_rc_expire_at` (`expire_at`),
  INDEX `idx_rc_source_key` (`api_source`, `cache_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='结果缓存（通用交付物缓存）';

-- ===== 收藏表 =====
CREATE TABLE IF NOT EXISTS `favorites` (
  `id`         BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `user_id`    BIGINT UNSIGNED NOT NULL,
  `item_type`  VARCHAR(16)  NOT NULL COMMENT '业务条目类型（由插件声明）',
  `item_id`    BIGINT UNSIGNED NOT NULL,
  `title`      VARCHAR(100) DEFAULT NULL,
  `sub`        VARCHAR(200) DEFAULT NULL,
  `payload`    JSON         DEFAULT NULL COMMENT '展示快照',
  `created_at` DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='用户收藏表';

-- ===== 商品表（SKU 化，价格以后端为准）=====
CREATE TABLE IF NOT EXISTS `products` (
  `id`           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `sku_code`     VARCHAR(40)   DEFAULT NULL,
  `product_type` VARCHAR(20)   DEFAULT 'report' COMMENT 'membership/single/tool_day/report',
  `feature`      VARCHAR(20)   DEFAULT NULL COMMENT '能力码（对应插件 Capability.code）',
  `name`         VARCHAR(100)  NOT NULL,
  `description`  TEXT,
  `price`        DECIMAL(10,2) NOT NULL,
  `modules`      JSON          DEFAULT NULL COMMENT '内容章节列表',
  `refund_rule`  VARCHAR(500)  DEFAULT NULL,
  `sort_order`   INT           DEFAULT 0,
  `enabled`      SMALLINT      DEFAULT 1,
  `created_at`   DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY `uk_sku` (`sku_code`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='商品表';

-- ===== 订单表 =====
CREATE TABLE IF NOT EXISTS `orders` (
  `id`             BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `order_no`       VARCHAR(32)     NOT NULL COMMENT '订单号',
  `user_id`        BIGINT UNSIGNED NOT NULL,
  `product_id`     BIGINT UNSIGNED DEFAULT NULL,
  `sku_code`       VARCHAR(40)     DEFAULT NULL,
  `product_type`   VARCHAR(20)     DEFAULT NULL,
  `product_name`   VARCHAR(100)    NOT NULL,
  `amount`         DECIMAL(10,2)   NOT NULL COMMENT '金额',
  `status`         VARCHAR(20)     DEFAULT 'pending'
                   COMMENT 'pending/completed/refunded/refund_pending/expired/cancelled',
  `pay_channel`    VARCHAR(10)     DEFAULT NULL COMMENT 'wechat/alipay/member',
  `result_ref_id`  BIGINT UNSIGNED DEFAULT NULL COMMENT '关联的前置计算/结果缓存记录ID',
  `input_snapshot` JSON            DEFAULT NULL COMMENT '入参快照',
  `biz_data`       JSON            DEFAULT NULL COMMENT '业务快照（由插件写入）',
  `inviter_id`     BIGINT UNSIGNED DEFAULT NULL COMMENT '下单时一级邀请人',
  `login_id_type`  VARCHAR(16)     DEFAULT NULL COMMENT '下单时登录标识类型快照',
  `login_id_value` VARCHAR(64)     DEFAULT NULL COMMENT '下单时登录标识值快照',
  `paid_at`        DATETIME        DEFAULT NULL,
  `pay_url`        VARCHAR(500)    DEFAULT NULL,
  `pay_trade_no`   VARCHAR(64)     DEFAULT NULL COMMENT '支付平台交易号',
  `fulfilled_at`   DATETIME        DEFAULT NULL COMMENT '履约完成时间',
  `fail_reason`    VARCHAR(200)    DEFAULT NULL COMMENT '支付/履约失败原因',
  `created_at`     DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`     DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY `uk_order_no` (`order_no`),
  INDEX `ix_orders_sku_code` (`sku_code`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='订单表';

-- ===== 会员身份表 =====
CREATE TABLE IF NOT EXISTS `user_memberships` (
  `id`              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `user_id`         BIGINT UNSIGNED NOT NULL,
  `level`           VARCHAR(20)  DEFAULT 'none' COMMENT 'none/month/year/lifetime',
  `start_at`        DATETIME     DEFAULT NULL,
  `expire_at`       DATETIME     DEFAULT NULL COMMENT '月/年会员到期时间，终身为NULL',
  `source_order_no` VARCHAR(32)  DEFAULT NULL,
  `bonus_quota`     INT          NOT NULL DEFAULT 0 COMMENT '赠送/补偿额度，优先扣减，周期/到期清零',
  `bonus_used`      INT          NOT NULL DEFAULT 0 COMMENT '本周期已用赠送额度',
  `period_start`    DATETIME     DEFAULT NULL COMMENT '当前额度周期起算（终身每365天滚动）',
  `continuous_flag` SMALLINT     NOT NULL DEFAULT 0 COMMENT '连续会员标记：宽限期内续费保留',
  `rule_version`    VARCHAR(20)  DEFAULT NULL COMMENT '购买时确认的规则版本号',
  `created_at`      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY `uk_user` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='用户会员身份';

-- ===== 会员发放/回滚流水表 =====
CREATE TABLE IF NOT EXISTS `membership_ledger` (
  `id`         BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `user_id`    BIGINT UNSIGNED NOT NULL,
  `order_id`   BIGINT UNSIGNED NOT NULL,
  `order_no`   VARCHAR(32) NOT NULL,
  `level`      VARCHAR(20) NOT NULL COMMENT 'month/year/lifetime',
  `grant_days` INT NOT NULL DEFAULT 0 COMMENT '本次发放天数，永久为0',
  `action`     VARCHAR(20) DEFAULT 'grant' COMMENT 'grant发放/rollback回滚/upgrade升级',
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX `ix_membership_ledger_user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='会员发放流水';

-- ===== 单次/按天权益表 =====
CREATE TABLE IF NOT EXISTS `user_entitlements` (
  `id`         BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `user_id`    BIGINT UNSIGNED NOT NULL,
  `sku_code`   VARCHAR(40) NOT NULL,
  `feature`    VARCHAR(20) NOT NULL COMMENT '能力码',
  `status`     VARCHAR(20) DEFAULT 'available' COMMENT 'available/used/expired/revoked',
  `order_id`   BIGINT UNSIGNED NOT NULL,
  `biz_key`    VARCHAR(64) DEFAULT NULL COMMENT '业务幂等键',
  `expire_at`  DATETIME DEFAULT NULL,
  `used_at`    DATETIME DEFAULT NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY `uk_order_feature` (`order_id`, `feature`),
  INDEX `ix_user_entitlements_user_id` (`user_id`),
  INDEX `ix_user_entitlements_feature` (`feature`),
  INDEX `ix_user_entitlements_order_id` (`order_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='单次/按天付费权益';

-- ===== 报告表 =====
CREATE TABLE IF NOT EXISTS `reports` (
  `id`          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `order_id`    BIGINT UNSIGNED NOT NULL COMMENT '一单一报告唯一约束',
  `user_id`     BIGINT UNSIGNED NOT NULL,
  `title`       VARCHAR(200) DEFAULT NULL,
  `chapters`    JSON         DEFAULT NULL COMMENT '报告章节 [{title, content}]',
  `status`      VARCHAR(20)  DEFAULT 'generating' COMMENT 'generating/completed/failed/refunded',
  `ai_meta`     JSON         DEFAULT NULL COMMENT 'AI 生成合成内容标识元数据',
  `viewed_at`   DATETIME     DEFAULT NULL COMMENT '用户首次查看时间（退款校验用）',
  `retry_count` SMALLINT     DEFAULT 0,
  `deleted_at`  DATETIME     DEFAULT NULL COMMENT '软删除',
  `created_at`  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY `uk_order` (`order_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='报告表';

-- ===== AI 生成合成内容日志留存表 =====
CREATE TABLE IF NOT EXISTS `ai_generation_logs` (
  `id`            BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `content_id`    VARCHAR(80)  NOT NULL COMMENT '内容编号 ProduceID',
  `user_id`       BIGINT UNSIGNED DEFAULT NULL,
  `order_id`      BIGINT UNSIGNED DEFAULT NULL,
  `report_id`     BIGINT UNSIGNED DEFAULT NULL,
  `scene`         VARCHAR(32)  DEFAULT NULL COMMENT '报告场景标识',
  `ai`            SMALLINT     NOT NULL DEFAULT 0 COMMENT '1 生成式大模型产出/0 第三方算法',
  `provider`      VARCHAR(100) DEFAULT NULL COMMENT '服务提供者名称',
  `model`         VARCHAR(60)  DEFAULT NULL COMMENT '大模型标识',
  `prompt_digest` VARCHAR(64)  DEFAULT NULL COMMENT '输入摘要 sha256 前 32 位',
  `input_chars`   INT          DEFAULT 0,
  `output_chars`  INT          DEFAULT 0,
  `status`        VARCHAR(20)  DEFAULT 'success' COMMENT 'success/failed/fallback',
  `remark`        VARCHAR(200) DEFAULT NULL,
  `created_at`    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX `ix_ai_generation_logs_content_id` (`content_id`),
  INDEX `ix_ai_generation_logs_user_id` (`user_id`),
  INDEX `ix_ai_generation_logs_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='AI 生成内容日志（留存≥6个月）';

-- ===== 退款表 =====
CREATE TABLE IF NOT EXISTS `refunds` (
  `id`          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `order_id`    BIGINT UNSIGNED NOT NULL,
  `user_id`     BIGINT UNSIGNED NOT NULL,
  `refund_no`   VARCHAR(40)  DEFAULT NULL COMMENT '商户退款单号（UUID防碰撞）',
  `reason`      VARCHAR(100) NOT NULL,
  `description` VARCHAR(200) DEFAULT NULL,
  `status`      VARCHAR(20)  DEFAULT 'pending_refund' COMMENT 'pending_refund/refunded/failed/processing',
  `retry_count` SMALLINT     DEFAULT 0,
  `fail_reason` VARCHAR(200) DEFAULT NULL,
  `created_at`  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX `ix_refunds_order_id` (`order_id`),
  -- L3：refund_no 唯一约束。退款回调可能重复投递、重试逻辑可能重复插入，无唯一键时
  -- 同一 refund_no 会落多行，_handle_wechat_refund 用 scalars().first() 只是掩盖症状
  -- （读到哪行不确定）。MySQL 唯一键允许多个 NULL，历史无单号行不受影响。
  UNIQUE KEY `uk_refund_no` (`refund_no`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='退款记录表';

-- ===== 渠道对账差错台账 =====
CREATE TABLE IF NOT EXISTS `reconciliation_diffs` (
  `id`               BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `diff_key`         VARCHAR(160) NOT NULL COMMENT '幂等键：bill_date|channel|diff_type|单号',
  `bill_date`        VARCHAR(10)  NOT NULL COMMENT '渠道账单日 YYYY-MM-DD',
  `channel`          VARCHAR(10)  NOT NULL COMMENT 'wechat/alipay',
  `diff_type`        VARCHAR(24)  NOT NULL COMMENT '差错类型',
  `order_no`         VARCHAR(32)  DEFAULT NULL,
  `channel_trade_no` VARCHAR(64)  DEFAULT NULL,
  `channel_amount`   DECIMAL(12,2) DEFAULT NULL,
  `local_amount`     DECIMAL(12,2) DEFAULT NULL,
  `channel_status`   VARCHAR(30)  DEFAULT NULL,
  `local_status`     VARCHAR(20)  DEFAULT NULL,
  `detail`           VARCHAR(500) DEFAULT NULL,
  `resolved`         SMALLINT     NOT NULL DEFAULT 0 COMMENT '0未处理 1已人工处理',
  `resolved_note`    VARCHAR(200) DEFAULT NULL,
  `resolved_at`      DATETIME     DEFAULT NULL,
  `created_at`       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY `uk_diff_key` (`diff_key`),
  INDEX `ix_reconciliation_diffs_bill_date` (`bill_date`),
  INDEX `ix_reconciliation_diffs_diff_type` (`diff_type`),
  INDEX `ix_reconciliation_diffs_order_no` (`order_no`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='对账差错台账';

-- ===== 反馈表 =====
CREATE TABLE IF NOT EXISTS `feedbacks` (
  `id`         BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `user_id`    BIGINT UNSIGNED NOT NULL,
  `type`       VARCHAR(20) NOT NULL,
  `content`    TEXT NOT NULL,
  `images`     JSON,
  `status`     VARCHAR(20) DEFAULT 'pending',
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='意见反馈表';

-- ===== 系统配置表 =====
CREATE TABLE IF NOT EXISTS `system_configs` (
  `id`           INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `config_key`   VARCHAR(50) NOT NULL,
  `config_value` JSON NOT NULL,
  `updated_at`   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY `uk_config_key` (`config_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='系统配置表';

-- ===== 推广员表（一级直推）=====
CREATE TABLE IF NOT EXISTS `distributors` (
  `id`                   BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `user_id`              BIGINT UNSIGNED NOT NULL,
  `invite_code`          VARCHAR(12) NOT NULL,
  `status`               SMALLINT DEFAULT 1 COMMENT '0冻结/注销 1正常 2违规封禁',
  `total_commission`     DECIMAL(12,2) DEFAULT 0,
  `pending_commission`   DECIMAL(12,2) DEFAULT 0,
  `available_commission` DECIMAL(12,2) DEFAULT 0,
  `withdrawn_commission` DECIMAL(12,2) DEFAULT 0,
  `debt_commission`      DECIMAL(12,2) DEFAULT 0 COMMENT '已结算佣金被退款冲回形成的负债',
  `invite_count`         INT DEFAULT 0,
  `paid_count`           INT DEFAULT 0,
  `level`                SMALLINT DEFAULT 0 COMMENT '当前生效等级 0普通/1高级/2合伙人',
  `verified_paid_count`  INT DEFAULT 0 COMMENT '累计验证付费用户数',
  `promo_baseline`       INT DEFAULT 0 COMMENT '降级重升基准',
  `next_level`           SMALLINT DEFAULT NULL COMMENT '待生效等级',
  `next_level_at`        DATETIME DEFAULT NULL,
  `level_updated_at`     DATETIME DEFAULT NULL,
  `exam_passed`          SMALLINT DEFAULT 0 COMMENT '是否通过合规入门考试',
  `consent_signed_at`    DATETIME DEFAULT NULL COMMENT '合规推广承诺书签署时点',
  `real_name`            VARCHAR(180) DEFAULT NULL COMMENT '提现实名（密文）',
  `frozen_until`         DATETIME DEFAULT NULL COMMENT '违规冻结到期时点',
  `link_disabled`        SMALLINT DEFAULT 0 COMMENT '断链：1=专属链接停用',
  `created_at`           DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY `uk_user` (`user_id`),
  UNIQUE KEY `uk_code` (`invite_code`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='推广员';

-- ===== 佣金流水表 =====
CREATE TABLE IF NOT EXISTS `commission_logs` (
  `id`             BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `distributor_id` BIGINT UNSIGNED NOT NULL,
  `buyer_id`       BIGINT UNSIGNED NOT NULL,
  `order_id`       BIGINT UNSIGNED NOT NULL,
  `order_no`       VARCHAR(32) NOT NULL,
  `order_amount`   DECIMAL(10,2) NOT NULL,
  `rate`           DECIMAL(5,4) NOT NULL COMMENT '实际生效费率',
  `base_rate`      DECIMAL(5,4) DEFAULT NULL COMMENT '下单时等级基础费率快照',
  `uplift_rate`    DECIMAL(5,4) DEFAULT 0 COMMENT '月度阶梯上浮',
  `level_snapshot` SMALLINT DEFAULT NULL COMMENT '下单时推广员等级',
  `month`          VARCHAR(7) DEFAULT NULL COMMENT '归属自然月 YYYY-MM',
  `amount`         DECIMAL(10,2) NOT NULL,
  `status`         VARCHAR(20) DEFAULT 'pending' COMMENT 'pending/settled/cancelled',
  `settled_at`     DATETIME DEFAULT NULL,
  `cancelled_at`   DATETIME DEFAULT NULL,
  `remark`         VARCHAR(200) DEFAULT NULL,
  `created_at`     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY `uk_order` (`order_id`),
  INDEX `ix_commission_logs_distributor_id` (`distributor_id`),
  INDEX `ix_commission_logs_month` (`month`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='佣金流水';

-- ===== 计佣失败重试表 =====
CREATE TABLE IF NOT EXISTS `commission_fail_logs` (
  `id`          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `order_id`    BIGINT UNSIGNED NOT NULL,
  `order_no`    VARCHAR(32) NOT NULL,
  `fail_reason` VARCHAR(300) DEFAULT NULL,
  `retry_count` SMALLINT DEFAULT 0,
  `status`      VARCHAR(20) DEFAULT 'pending' COMMENT 'pending/success/abandoned',
  `created_at`  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX `ix_commission_fail_logs_order_id` (`order_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='计佣失败记录';

-- ===== 提现申请表 =====
CREATE TABLE IF NOT EXISTS `withdrawals` (
  `id`             BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `withdraw_no`    VARCHAR(32) NOT NULL,
  `distributor_id` BIGINT UNSIGNED NOT NULL,
  `user_id`        BIGINT UNSIGNED NOT NULL,
  `amount`         DECIMAL(10,2) NOT NULL COMMENT '提现申请总额（税前）',
  `tax_amount`     DECIMAL(10,2) DEFAULT 0 COMMENT '代扣个税金额',
  `actual_amount`  DECIMAL(10,2) DEFAULT NULL COMMENT '税后实际打款金额',
  `status`         VARCHAR(20) DEFAULT 'auditing' COMMENT 'auditing/paid/rejected',
  `channel`        VARCHAR(10) NOT NULL,
  `account_name`   VARCHAR(180) NOT NULL COMMENT '收款人姓名（密文）',
  `account_no`     VARCHAR(255) NOT NULL COMMENT '收款账号（密文）',
  `remark`         VARCHAR(200) DEFAULT NULL,
  `count_refunded` SMALLINT DEFAULT 0 COMMENT '1=当次提现次数已返还',
  `fail_reason`    VARCHAR(200) DEFAULT NULL,
  `audited_at`     DATETIME DEFAULT NULL,
  `auditor`        VARCHAR(50) DEFAULT NULL,
  `created_at`     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY `uk_withdraw_no` (`withdraw_no`),
  INDEX `ix_withdrawals_distributor_id` (`distributor_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='提现申请';

-- ===== 推广触达记录（归因）=====
CREATE TABLE IF NOT EXISTS `attribution_touches` (
  `id`             BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `visitor_key`    VARCHAR(64) NOT NULL COMMENT '未注册访客标识',
  `invite_code`    VARCHAR(12) NOT NULL,
  `distributor_id` BIGINT UNSIGNED NOT NULL,
  `ip`             VARCHAR(45) DEFAULT NULL,
  `user_agent`     VARCHAR(255) DEFAULT NULL,
  `touched_at`     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `bound_user_id`  BIGINT UNSIGNED DEFAULT NULL COMMENT '归因绑定的注册用户',
  INDEX `ix_attribution_touches_visitor_key` (`visitor_key`),
  INDEX `ix_attribution_touches_invite_code` (`invite_code`),
  INDEX `ix_attribution_touches_distributor_id` (`distributor_id`),
  INDEX `ix_attribution_touches_touched_at` (`touched_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='推广触达记录';

-- ===== 验证付费用户台账 =====
CREATE TABLE IF NOT EXISTS `verified_paid_users` (
  `id`             BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `distributor_id` BIGINT UNSIGNED NOT NULL,
  `buyer_id`       BIGINT UNSIGNED NOT NULL COMMENT '终身只计一次',
  `first_order_id` BIGINT UNSIGNED DEFAULT NULL,
  `first_paid_at`  DATETIME DEFAULT NULL,
  `verify_at`      DATETIME DEFAULT NULL COMMENT '过退款期时点=首付+7天',
  `status`         SMALLINT DEFAULT 0 COMMENT '0待过退款期/1已计入/2退款回退',
  `created_at`     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY `uk_buyer` (`buyer_id`),
  INDEX `ix_verified_paid_users_distributor_id` (`distributor_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='验证付费用户台账';

-- ===== 月度业绩表 =====
CREATE TABLE IF NOT EXISTS `monthly_performances` (
  `id`             BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `distributor_id` BIGINT UNSIGNED NOT NULL,
  `month`          VARCHAR(7) NOT NULL COMMENT '自然月 YYYY-MM',
  `total_amount`   DECIMAL(12,2) DEFAULT 0 COMMENT '月度推广总金额（支付成功扣退款）',
  `ladder_uplift`  DECIMAL(5,4) DEFAULT 0 COMMENT '最终阶梯档位上浮',
  `ladder_adjust`  DECIMAL(12,2) DEFAULT 0 COMMENT '阶梯差额补发/追回',
  `final_rank`     INT DEFAULT NULL COMMENT '最终名次（仅前20）',
  `rank_reward`    DECIMAL(10,2) DEFAULT 0 COMMENT '排行榜奖金',
  `clawback`       DECIMAL(12,2) DEFAULT 0 COMMENT '结算后追回',
  `disqualified`   SMALLINT DEFAULT 0 COMMENT '1=取消当月奖励资格',
  `settled`        SMALLINT DEFAULT 0 COMMENT '0未结算/1已结算',
  `settled_at`     DATETIME DEFAULT NULL,
  `created_at`     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY `uq_perf_dist_month` (`distributor_id`, `month`),
  INDEX `ix_monthly_performances_distributor_id` (`distributor_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='月度业绩';

-- ===== 合规入门考试题库 =====
CREATE TABLE IF NOT EXISTS `exam_questions` (
  `id`         BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `category`   VARCHAR(50) DEFAULT NULL COMMENT '所属红线类别',
  `content`    TEXT NOT NULL COMMENT '题干',
  `options`    JSON DEFAULT NULL COMMENT '选项数组',
  `answer`     VARCHAR(20) NOT NULL COMMENT '正确答案',
  `qtype`      VARCHAR(10) DEFAULT 'single' COMMENT 'single/multiple/judge',
  `score`      INT DEFAULT 5,
  `sort_order` INT DEFAULT 0,
  `enabled`    SMALLINT DEFAULT 1,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='合规入门考试题库';

-- ===== 考试记录 =====
CREATE TABLE IF NOT EXISTS `exam_records` (
  `id`             BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `user_id`        BIGINT UNSIGNED NOT NULL,
  `distributor_id` BIGINT UNSIGNED DEFAULT NULL,
  `score`          INT DEFAULT 0,
  `passed`         SMALLINT DEFAULT 0 COMMENT '1=达到及格分',
  `answers`        JSON DEFAULT NULL,
  `attempt_no`     INT DEFAULT 1,
  `created_at`     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX `ix_exam_records_user_id` (`user_id`),
  INDEX `ix_exam_records_distributor_id` (`distributor_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='考试记录（留痕≥3年）';

-- ===== 合规留痕 =====
CREATE TABLE IF NOT EXISTS `compliance_consents` (
  `id`             BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `user_id`        BIGINT UNSIGNED NOT NULL,
  `distributor_id` BIGINT UNSIGNED DEFAULT NULL,
  `doc_type`       VARCHAR(30) NOT NULL COMMENT 'promoter_commitment/payment_disclaimer/rule_change',
  `doc_version`    VARCHAR(20) DEFAULT NULL,
  `agreed`         SMALLINT DEFAULT 1,
  `order_id`       BIGINT UNSIGNED DEFAULT NULL,
  `ip`             VARCHAR(45) DEFAULT NULL,
  `user_agent`     VARCHAR(255) DEFAULT NULL,
  `agreed_at`      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX `ix_compliance_consents_user_id` (`user_id`),
  INDEX `ix_compliance_consents_distributor_id` (`distributor_id`),
  INDEX `ix_compliance_consents_agreed_at` (`agreed_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='合规留痕（≥3年）';

-- ===== 合规评估记录 =====
CREATE TABLE IF NOT EXISTS `compliance_assessments` (
  `id`             BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `risk_item`      VARCHAR(20) NOT NULL COMMENT '风险清单编号',
  `topic`          VARCHAR(100) NOT NULL,
  `scope_desc`     TEXT,
  `legal_basis`    VARCHAR(300) DEFAULT NULL,
  `finding`        TEXT,
  `conclusion`     VARCHAR(20) DEFAULT 'rectified' COMMENT 'rectified/acceptable/pending/rejected',
  `measures`       TEXT,
  `opinion`        TEXT,
  `assessor`       VARCHAR(50) DEFAULT NULL,
  `assessed_at`    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `next_review_at` DATETIME DEFAULT NULL,
  `evidence`       JSON DEFAULT NULL,
  `status`         SMALLINT DEFAULT 1 COMMENT '1有效 0已作废',
  `created_at`     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX `ix_compliance_assessments_risk_item` (`risk_item`),
  INDEX `ix_compliance_assessments_assessed_at` (`assessed_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='合规评估记录';

-- ===== 敏感词库 =====
CREATE TABLE IF NOT EXISTS `sensitive_words` (
  `id`         BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `word`       VARCHAR(50) NOT NULL,
  `level`      SMALLINT DEFAULT 2 COMMENT '1一级拦截/2二级预警',
  `category`   VARCHAR(50) DEFAULT NULL,
  `enabled`    SMALLINT DEFAULT 1,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY `uk_word` (`word`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='敏感词库';

-- ===== 外部推广账号报备 =====
CREATE TABLE IF NOT EXISTS `external_accounts` (
  `id`             BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `distributor_id` BIGINT UNSIGNED NOT NULL,
  `user_id`        BIGINT UNSIGNED NOT NULL,
  `platform`       VARCHAR(30) NOT NULL COMMENT '抖音/快手/小红书/视频号/公众号/B站/微博等',
  `account_name`   VARCHAR(100) NOT NULL,
  `account_url`    VARCHAR(255) DEFAULT NULL,
  `status`         SMALLINT DEFAULT 0 COMMENT '0待审/1通过/2拒绝',
  `remark`         VARCHAR(200) DEFAULT NULL,
  `created_at`     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX `ix_external_accounts_distributor_id` (`distributor_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='外部推广账号报备';

-- ===== 举报工单 =====
CREATE TABLE IF NOT EXISTS `report_tickets` (
  `id`                   BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `reporter_id`          BIGINT UNSIGNED DEFAULT NULL COMMENT '举报人，可匿名',
  `target_distributor_id` BIGINT UNSIGNED DEFAULT NULL,
  `target_type`          VARCHAR(30) DEFAULT NULL COMMENT 'distributor/content/order',
  `content`              TEXT NOT NULL,
  `evidence`             JSON DEFAULT NULL,
  `contact`              VARCHAR(100) DEFAULT NULL,
  `status`               SMALLINT DEFAULT 0 COMMENT '0待处理/1处理中/2已处置/3已驳回',
  `handler`              VARCHAR(50) DEFAULT NULL,
  `handle_result`        VARCHAR(500) DEFAULT NULL,
  `responded_at`         DATETIME DEFAULT NULL,
  `created_at`           DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`           DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX `ix_report_tickets_reporter_id` (`reporter_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='举报工单';

-- ===== 违规分级处置记录 =====
CREATE TABLE IF NOT EXISTS `violation_records` (
  `id`               BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `distributor_id`   BIGINT UNSIGNED NOT NULL,
  `user_id`          BIGINT UNSIGNED DEFAULT NULL,
  `level`            VARCHAR(12) NOT NULL COMMENT 'minor/moderate/severe/illegal',
  `action`           VARCHAR(30) DEFAULT NULL COMMENT 'warn/freeze/terminate/exit',
  `reason`           VARCHAR(500) DEFAULT NULL,
  `evidence`         JSON DEFAULT NULL,
  `order_id`         BIGINT UNSIGNED DEFAULT NULL,
  `report_ticket_id` BIGINT UNSIGNED DEFAULT NULL,
  `frozen_until`     DATETIME DEFAULT NULL,
  `level_before`     SMALLINT DEFAULT NULL,
  `level_after`      SMALLINT DEFAULT NULL,
  `clawback_amount`  DECIMAL(12,2) DEFAULT 0,
  `handler`          VARCHAR(50) DEFAULT NULL,
  `status`           VARCHAR(20) DEFAULT 'applied' COMMENT 'applied已处置/revoked已撤销',
  `created_at`       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX `ix_violation_records_distributor_id` (`distributor_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='违规处置记录（留痕≥3年）';

-- ===== 管理操作审计日志 =====
CREATE TABLE IF NOT EXISTS `admin_operation_logs` (
  `id`          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `action`      VARCHAR(50) NOT NULL COMMENT 'refund/grant_membership/audit_withdrawal 等',
  `target_type` VARCHAR(30) DEFAULT NULL COMMENT 'order/user/withdrawal',
  `target_id`   VARCHAR(40) DEFAULT NULL,
  `detail`      TEXT COMMENT '操作前后值快照JSON',
  `ip`          VARCHAR(45) DEFAULT NULL,
  `created_at`  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='管理操作审计日志';

-- ===== 电子发票申请台账 =====
CREATE TABLE IF NOT EXISTS `invoice_requests` (
  `id`             BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `apply_no`       VARCHAR(32) NOT NULL COMMENT '申请单号',
  `order_id`       BIGINT UNSIGNED NOT NULL COMMENT '一单一票',
  `order_no`       VARCHAR(32) NOT NULL,
  `user_id`        BIGINT UNSIGNED NOT NULL,
  `amount`         DECIMAL(10,2) NOT NULL COMMENT '开票金额（订单实付快照）',
  `product_name`   VARCHAR(100) DEFAULT NULL,
  `invoice_type`   VARCHAR(20) NOT NULL DEFAULT 'personal' COMMENT 'personal/company',
  `title`          VARCHAR(200) NOT NULL COMMENT '发票抬头',
  `tax_no`         VARCHAR(30) DEFAULT NULL COMMENT '纳税人识别号（企业必填）',
  `email`          VARCHAR(100) NOT NULL COMMENT '电子发票接收邮箱',
  `remark`         VARCHAR(200) DEFAULT NULL,
  `status`         VARCHAR(20) NOT NULL DEFAULT 'pending' COMMENT 'pending/issued/rejected/cancelled',
  `invoice_no`     VARCHAR(60) DEFAULT NULL,
  `invoice_code`   VARCHAR(30) DEFAULT NULL,
  `item_name`      VARCHAR(100) DEFAULT NULL COMMENT '开票项目名快照',
  `issued_at`      DATETIME DEFAULT NULL,
  `delivery`       VARCHAR(20) DEFAULT NULL COMMENT 'email/link/offline',
  `invoice_file`   VARCHAR(500) DEFAULT NULL,
  `reject_reason`  VARCHAR(200) DEFAULT NULL,
  `need_red_flush` SMALLINT NOT NULL DEFAULT 0 COMMENT '1=已开票后退款需红冲',
  `handler`        VARCHAR(50) DEFAULT NULL,
  `created_at`     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY `uk_apply_no` (`apply_no`),
  UNIQUE KEY `uk_order` (`order_id`),
  INDEX `ix_invoice_requests_order_no` (`order_no`),
  INDEX `ix_invoice_requests_user_id` (`user_id`),
  INDEX `ix_invoice_requests_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='电子发票申请台账';

-- ===== 卡券批次 =====
CREATE TABLE IF NOT EXISTS `card_batches` (
  `id`          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `batch_no`    VARCHAR(32) NOT NULL,
  `sku_code`    VARCHAR(40) NOT NULL,
  `total_count` INT DEFAULT 0,
  `used_count`  INT DEFAULT 0,
  `remark`      VARCHAR(200) DEFAULT NULL,
  `expire_at`   DATETIME DEFAULT NULL,
  `created_by`  VARCHAR(50) DEFAULT NULL,
  `created_at`  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY `uk_batch_no` (`batch_no`),
  INDEX `ix_card_batches_sku_code` (`sku_code`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='卡券批次';

-- ===== 卡券码 =====
CREATE TABLE IF NOT EXISTS `card_codes` (
  `id`              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `code`            VARCHAR(32) NOT NULL,
  `sku_code`        VARCHAR(40) NOT NULL,
  `batch_id`        BIGINT UNSIGNED DEFAULT NULL,
  `source`          VARCHAR(10) DEFAULT 'batch',
  `source_order_no` VARCHAR(32) DEFAULT NULL,
  `status`          VARCHAR(10) DEFAULT 'unused' COMMENT 'unused/used/disabled',
  `used_by`         BIGINT UNSIGNED DEFAULT NULL,
  `used_at`         DATETIME DEFAULT NULL,
  `expire_at`       DATETIME DEFAULT NULL,
  `redeem_order_no` VARCHAR(32) DEFAULT NULL,
  `created_at`      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY `uk_code` (`code`),
  UNIQUE KEY `uk_card_source_order` (`source`, `source_order_no`),
  INDEX `ix_card_codes_batch_id` (`batch_id`),
  INDEX `ix_card_codes_status` (`status`),
  INDEX `ix_card_codes_used_by` (`used_by`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='卡券码';

-- ============================================
-- 初始化系统配置（通用；不含任何垂直业务项）
-- ============================================
INSERT INTO `system_configs` (`config_key`, `config_value`) VALUES
  ('paid_reports_enabled', 'true'),
  ('refund_enabled', 'true'),
  ('invoice_enabled', 'true'),
  ('distribution_enabled', 'true'),
  ('announcement', '""'),
  ('theme', '{"primary_color":"#3B82F6","accent_color":"#2563EB","danger_color":"#e64340"}'),
  ('commission_rate', '0.30'),
  ('commission_settle_days', '7'),
  ('withdraw_min', '10.00'),
  ('membership_month_days', '30')
ON DUPLICATE KEY UPDATE `config_value` = VALUES(`config_value`);

-- ============================================
-- 初始化会员档位商品（通用三档；具体能力商品由业务插件的 manifest 声明后写入）
-- 定价与 config.MEMBERSHIP_* 及 main._seed_base_data 保持一致。
-- ============================================
INSERT INTO `products` (`sku_code`, `product_type`, `feature`, `name`, `description`, `price`, `refund_rule`, `sort_order`, `enabled`) VALUES
  ('vip_month',    'membership', 'vip', '月卡会员',   '开通起30天：会员权益、周期总额度100次、单能力单日10次',                                             99.00,  '虚拟内容服务，支付后7天内未使用可联系客服退款', 1, 1),
  ('vip_year',     'membership', 'vip', '年卡会员',   '开通起365天：会员权益、周期总额度1200次、单能力单日50次、优先客服',                                299.00, '虚拟内容服务，支付后7天内未使用可联系客服退款', 2, 1),
  ('vip_lifetime', 'membership', 'vip', '终身会员',   '平台运营期内永久：会员权益、每365天周期总额度3000次、单能力单日100次、最高优先客服',               599.00, '虚拟内容服务，支付后7天内未使用可联系客服退款', 3, 1)
ON DUPLICATE KEY UPDATE
  `name`=VALUES(`name`), `description`=VALUES(`description`), `price`=VALUES(`price`),
  `product_type`=VALUES(`product_type`), `feature`=VALUES(`feature`);
