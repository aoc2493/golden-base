-- ============================================================
-- 0001：存量库补齐 users.email / users.password_hash、orders 与举报/违规表索引
--
-- 背景：init.sql 的 users 表此前缺少这两列，而 ORM（app/core/models.py）里有。
-- 由 init.sql 建出的库在启动后不会报错，但任何 select(User)/insert(User) 都会
-- 抛 1054 Unknown column —— 登录、注册及所有鉴权接口全部 500。
-- 另补齐两个仅 ORM 声明的查询索引（举报按被举报人、违规记录按用户），缺了不报错，
-- 但后台按这两列过滤时会走全表扫描。
--
-- 用法（只在存量库上执行一次；全新库直接由 init.sql 建表，不要跑本文件）：
--   docker compose exec -T mysql mysql -u"$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" \
--     < sql/migrations/0001_users_email_and_orders_index.sql
--
-- 幂等：全部通过 information_schema 判存在性后再执行，可重复运行。
-- 执行前请自行备份（mysqldump --single-transaction）。
-- ============================================================

SET @db := DATABASE();

-- users.email
SET @exists := (SELECT COUNT(*) FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'users' AND COLUMN_NAME = 'email');
SET @ddl := IF(@exists = 0,
  'ALTER TABLE `users` ADD COLUMN `email` VARCHAR(255) DEFAULT NULL COMMENT ''邮箱（Web 站注册登录）'' AFTER `unionid`',
  'DO 0');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- users.password_hash
SET @exists := (SELECT COUNT(*) FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'users' AND COLUMN_NAME = 'password_hash');
SET @ddl := IF(@exists = 0,
  'ALTER TABLE `users` ADD COLUMN `password_hash` VARCHAR(255) DEFAULT NULL COMMENT ''密码摘要 pbkdf2_sha256$迭代$盐$摘要'' AFTER `email`',
  'DO 0');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- users.email 唯一索引（MySQL 唯一索引允许多个 NULL，存量行不受影响）
SET @exists := (SELECT COUNT(*) FROM information_schema.STATISTICS
                WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'users' AND INDEX_NAME = 'uk_users_email');
SET @ddl := IF(@exists = 0,
  'ALTER TABLE `users` ADD UNIQUE KEY `uk_users_email` (`email`)',
  'DO 0');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- orders 索引：user_id 与 (status, created_at)
SET @exists := (SELECT COUNT(*) FROM information_schema.STATISTICS
                WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'orders' AND INDEX_NAME = 'ix_orders_user_id');
SET @ddl := IF(@exists = 0,
  'ALTER TABLE `orders` ADD INDEX `ix_orders_user_id` (`user_id`)',
  'DO 0');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @exists := (SELECT COUNT(*) FROM information_schema.STATISTICS
                WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'orders' AND INDEX_NAME = 'ix_orders_status_created');
SET @ddl := IF(@exists = 0,
  'ALTER TABLE `orders` ADD INDEX `ix_orders_status_created` (`status`, `created_at`)',
  'DO 0');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- report_tickets.target_distributor_id：后台按「被举报推广员」筛选
SET @exists := (SELECT COUNT(*) FROM information_schema.STATISTICS
                WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'report_tickets'
                  AND INDEX_NAME = 'ix_report_tickets_target_distributor_id');
SET @ddl := IF(@exists = 0,
  'ALTER TABLE `report_tickets` ADD INDEX `ix_report_tickets_target_distributor_id` (`target_distributor_id`)',
  'DO 0');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- violation_records.user_id：违规档案按用户反查
SET @exists := (SELECT COUNT(*) FROM information_schema.STATISTICS
                WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'violation_records'
                  AND INDEX_NAME = 'ix_violation_records_user_id');
SET @ddl := IF(@exists = 0,
  'ALTER TABLE `violation_records` ADD INDEX `ix_violation_records_user_id` (`user_id`)',
  'DO 0');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SELECT '0001 applied' AS result;
