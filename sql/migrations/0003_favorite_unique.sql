-- ============================================================
-- 0003：收藏表补「每人每条目唯一」约束（并先去掉历史重复行）
--
-- 背景：favorites 当前没有任何唯一约束，而 api/favorite.py 的查重是「先 SELECT 再 INSERT」，
-- 两步之间没有锁。双击/多标签并发会写进两行，随后：
--   · 查重走 scalar_one_or_none，读到两行即抛 MultipleResultsFound → 该条目此后每次收藏都 500；
--   · 收藏页出现两条一模一样的条目，取消收藏只能删掉其中一条。
-- 代码侧已改为 SAVEPOINT + 唯一约束兜底，本脚本把库里既有的重复行清掉并补上约束；
-- 不跑本脚本，MySQL 侧的并发兜底就只剩「读到两行报错」这一半。
--
-- 用法（只在存量库上执行一次；全新库直接由 init.sql 建表，不要跑本文件）：
--   docker compose exec -T mysql mysql -u"$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" \
--     < sql/migrations/0003_favorite_unique.sql
--
-- 幂等：先判断 uk_favorite_item 是否已存在，已存在则整体跳过（重复行也不再去删）。
-- 去重保留 id 最小的一条（最早那次收藏），后写的重复快照丢弃。
-- 执行前请自行备份（mysqldump --single-transaction）。
-- ============================================================

SET @db := DATABASE();

SET @exists := (SELECT COUNT(*) FROM information_schema.STATISTICS
                WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'favorites'
                  AND INDEX_NAME = 'uk_favorite_item');

-- 1) 去重：只在约束还没建时执行（建好约束后不可能再有重复行）
SET @ddl := IF(@exists = 0,
  'DELETE f FROM `favorites` f JOIN `favorites` g
     ON f.`user_id` = g.`user_id` AND f.`item_type` = g.`item_type`
    AND f.`item_id` = g.`item_id` AND f.`id` > g.`id`',
  'DO 0');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- 2) 补唯一约束（user_id 是最左前缀，收藏列表的 WHERE user_id 也走这条索引）
SET @ddl := IF(@exists = 0,
  'ALTER TABLE `favorites` ADD UNIQUE KEY `uk_favorite_item` (`user_id`, `item_type`, `item_id`)',
  'DO 0');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SELECT '0003 applied' AS result;
