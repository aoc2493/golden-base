-- ============================================================
-- 0004：orders 的用户侧列表改为复合索引（消除 filesort）
--
-- 背景：GET /api/order/list 是 `WHERE user_id=? [AND status=?] ORDER BY created_at DESC
-- LIMIT n`。原先只有单列 ix_orders_user_id：定位到该用户的行之后仍要回表 + filesort，
-- 订单数是全库增长最快的一张表，重度用户的「我的订单」翻页会随订单量线性变慢。
-- 复合 (user_id, created_at) 的最左前缀就是 user_id，所以只按 user_id 过滤的查询
-- （后台列表、退款/权益反查）照用同一条索引，单列索引成了冗余，一并删掉。
--
-- 用法（只在存量库上执行一次；全新库直接由 init.sql 建表，不要跑本文件）：
--   docker compose exec -T mysql mysql -u"$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" \
--     < sql/migrations/0004_orders_user_created_index.sql
--
-- 幂等：先查 information_schema.STATISTICS 再决定执行，可重复运行。
-- ADD INDEX 在 MySQL 8 下是 INPLACE、不锁写；大表建议放在低峰执行。
-- ============================================================

SET @db := DATABASE();

-- 1) 补复合索引
SET @exists := (SELECT COUNT(*) FROM information_schema.STATISTICS
                WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'orders'
                  AND INDEX_NAME = 'ix_orders_user_created');
SET @ddl := IF(@exists = 0,
  'ALTER TABLE `orders` ADD INDEX `ix_orders_user_created` (`user_id`, `created_at`)',
  'DO 0');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- 2) 删掉被最左前缀覆盖的单列索引（仅在复合索引已就位后才删）
SET @has_new := (SELECT COUNT(*) FROM information_schema.STATISTICS
                 WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'orders'
                   AND INDEX_NAME = 'ix_orders_user_created');
SET @has_old := (SELECT COUNT(*) FROM information_schema.STATISTICS
                 WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'orders'
                   AND INDEX_NAME = 'ix_orders_user_id');
SET @ddl := IF(@has_new > 0 AND @has_old > 0,
  'ALTER TABLE `orders` DROP INDEX `ix_orders_user_id`',
  'DO 0');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SELECT '0004 applied' AS result;
