-- Serialize pending orders per user/SKU and add durable password-reset tickets.
-- Safe to run repeatedly.

SET @db_name = DATABASE();

SET @has_auth_version = (
  SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = @db_name AND TABLE_NAME = 'users'
    AND COLUMN_NAME = 'auth_version'
);
SET @sql = IF(
  @has_auth_version = 0,
  'ALTER TABLE `users` ADD COLUMN `auth_version` INT NOT NULL DEFAULT 0 COMMENT ''改密后递增，撤销旧会话'' AFTER `password_hash`',
  'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Resolve historical duplicates before adding the unique key: keep the newest
-- pending order for each user/SKU and cancel older duplicate rows.
UPDATE `orders` o
JOIN (
  SELECT `user_id`, `sku_code`, MAX(`id`) AS keep_id
  FROM `orders`
  WHERE `status` = 'pending'
  GROUP BY `user_id`, `sku_code`
  HAVING COUNT(*) > 1
) d
  ON d.`user_id` = o.`user_id`
 AND d.`sku_code` = o.`sku_code`
 AND d.keep_id <> o.`id`
SET o.`status` = 'cancelled',
    o.`fail_reason` = '历史重复待支付单自动关闭'
WHERE o.`status` = 'pending';

SET @has_active_key = (
  SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = @db_name AND TABLE_NAME = 'orders'
    AND COLUMN_NAME = 'active_key'
);
SET @sql = IF(
  @has_active_key = 0,
  'ALTER TABLE `orders` ADD COLUMN `active_key` VARCHAR(20) DEFAULT NULL COMMENT ''pending 时为 active，终态置 NULL'' AFTER `status`',
  'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

UPDATE `orders` SET `active_key` = 'active' WHERE `status` = 'pending';
UPDATE `orders` SET `active_key` = NULL WHERE `status` <> 'pending';

SET @has_order_intent_index = (
  SELECT COUNT(*) FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA = @db_name AND TABLE_NAME = 'orders'
    AND INDEX_NAME = 'uk_order_active_intent'
);
SET @sql = IF(
  @has_order_intent_index = 0,
  'ALTER TABLE `orders` ADD UNIQUE KEY `uk_order_active_intent` (`user_id`, `sku_code`, `active_key`)',
  'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

CREATE TABLE IF NOT EXISTS `password_reset_tickets` (
  `id`          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `user_id`     BIGINT UNSIGNED NOT NULL,
  `email`       VARCHAR(255) NOT NULL,
  `code_hash`   VARCHAR(64) NOT NULL,
  `status`      VARCHAR(20) DEFAULT 'pending' COMMENT 'pending/used/expired/manual',
  `delivered`   SMALLINT NOT NULL DEFAULT 0,
  `expires_at`  DATETIME NOT NULL,
  `used_at`     DATETIME DEFAULT NULL,
  `created_at`  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX `ix_password_reset_email_status` (`email`, `status`),
  INDEX `ix_password_reset_user_status` (`user_id`, `status`),
  INDEX `ix_password_reset_expires_at` (`expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='密码重置工单';
