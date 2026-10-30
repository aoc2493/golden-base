-- ============================================================
-- 0002：放宽登录标识快照列宽（users.last_login_value / orders.login_id_value）
--
-- 背景：两列原为 VARCHAR(64)，但写入值包含登录邮箱，而 schemas 允许 email 到 255 字符。
-- MySQL 严格模式下超宽不是截断而是报错（1406 Data too long），故障表现为：
--   · 用 65+ 位邮箱注册/登录 → 写 users.last_login_value 时 500（账号已建、会话没发）；
--   · 该账号随后下单 → 写 orders.login_id_value 时 500（下单必失败）。
-- 设备码/openid 均 ≤64，只有邮箱会越界，所以目前只在长邮箱账号上可复现。
--
-- 用法（只在存量库上执行一次；全新库直接由 init.sql 建表，不要跑本文件）：
--   docker compose exec -T mysql mysql -u"$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" \
--     < sql/migrations/0002_login_id_value_width.sql
--
-- 幂等：先查 information_schema.COLUMNS 的当前宽度，只有仍是 64 才改，可重复运行。
-- VARCHAR(64)→VARCHAR(255) 在 MySQL 8 / utf8mb4 下是 INPLACE 变更、不重建表；
-- 执行前仍建议备份（mysqldump --single-transaction）。
-- ============================================================

SET @db := DATABASE();

-- users.last_login_value
SET @w := (SELECT CHARACTER_MAXIMUM_LENGTH FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'users' AND COLUMN_NAME = 'last_login_value');
SET @ddl := IF(@w = 64,
  'ALTER TABLE `users` MODIFY COLUMN `last_login_value` VARCHAR(255) DEFAULT NULL COMMENT ''最近登录标识值（邮箱可达255）''',
  'DO 0');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- orders.login_id_value
SET @w := (SELECT CHARACTER_MAXIMUM_LENGTH FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'orders' AND COLUMN_NAME = 'login_id_value');
SET @ddl := IF(@w = 64,
  'ALTER TABLE `orders` MODIFY COLUMN `login_id_value` VARCHAR(255) DEFAULT NULL COMMENT ''下单时登录标识值快照''',
  'DO 0');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SELECT '0002 applied' AS result;
