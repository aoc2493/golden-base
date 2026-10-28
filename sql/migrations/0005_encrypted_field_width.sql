-- ============================================================
-- 0005：放宽加密敏感字段列宽（distributors.real_name / withdrawals.account_name / account_no）
--
-- 背景：三列存的是 AES-256-GCM 密文（enc:v1: + base64(nonce12 || ct || tag16)）。
-- 原宽度按 ASCII 明文估算（180/255），但接口没有限制字符集：
--   · WithdrawRequest.account_name 允许 50 字 → 50 个汉字是 150 字节 → 密文 247 字符 > 180；
--   · WithdrawRequest.account_no    允许 100 字 → 300 字节 → 密文 447 字符 > 255。
-- 后果取决于 sql_mode：
--   · 严格模式（MySQL 8 默认）报 1406 Data too long，整个提现申请事务失败；
--   · 非严格模式**静默截断**，截断的密文认证标签永远验不过——这笔提现既打不出去，
--     收款人姓名/账号也不可恢复，只剩日志里一条 CRITICAL「敏感字段解密失败」。
-- 触发面很小（汉族两字姓名加密后 39 字符，远在宽度内），但一旦触发落在资金出口，
-- 故按「接口允许的最坏明文」实测值统一放到 512，并由
-- tests/test_crypto_field.py::test_worst_case_ciphertext_fits_the_column 常驻校验。
--
-- 用法（只在存量库上执行一次；全新库直接由 init.sql 建表，不要跑本文件）：
--   docker compose exec -T mysql mysql -u"$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" \
--     < sql/migrations/0005_encrypted_field_width.sql
--
-- 幂等：只在当前宽度 < 512 时执行 ALTER，可重复运行。
-- VARCHAR(180/255)→VARCHAR(512) 在 MySQL 8 / utf8mb4 下是 INPLACE 变更、不重建表。
--
-- 执行后请核对是否已有被截断的存量行（本迁移不猜测、也不覆盖它们的内容）：
--   SELECT id, CHAR_LENGTH(account_no) FROM withdrawals
--    WHERE account_no LIKE 'enc:v1:%' AND CHAR_LENGTH(account_no) IN (180, 255);
-- 命中的行需要联系收款人重新采集实名与账号；后台提现详情会以「敏感字段解密失败」暴露同一批行。
-- ============================================================

SET @db := DATABASE();

-- distributors.real_name
SET @w := (SELECT CHARACTER_MAXIMUM_LENGTH FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'distributors' AND COLUMN_NAME = 'real_name');
SET @ddl := IF(@w IS NOT NULL AND @w < 512,
  'ALTER TABLE `distributors` MODIFY COLUMN `real_name` VARCHAR(512) DEFAULT NULL COMMENT ''提现实名（密文，宽度见 0005 迁移）''',
  'DO 0');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- withdrawals.account_name
SET @w := (SELECT CHARACTER_MAXIMUM_LENGTH FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'withdrawals' AND COLUMN_NAME = 'account_name');
SET @ddl := IF(@w IS NOT NULL AND @w < 512,
  'ALTER TABLE `withdrawals` MODIFY COLUMN `account_name` VARCHAR(512) NOT NULL COMMENT ''收款人姓名（密文，宽度见 0005 迁移）''',
  'DO 0');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- withdrawals.account_no
SET @w := (SELECT CHARACTER_MAXIMUM_LENGTH FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'withdrawals' AND COLUMN_NAME = 'account_no');
SET @ddl := IF(@w IS NOT NULL AND @w < 512,
  'ALTER TABLE `withdrawals` MODIFY COLUMN `account_no` VARCHAR(512) NOT NULL COMMENT ''收款账号（密文，宽度见 0005 迁移）''',
  'DO 0');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SELECT '0005 applied' AS result;
