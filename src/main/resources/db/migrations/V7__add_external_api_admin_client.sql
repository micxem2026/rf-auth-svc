-- ============================================================
-- V7: Поддержка внешнего API для admin_client
--
-- 1. Добавляет created_by в таблицу users (кем создан пользователь)
-- 2. Backfill created_by для существующих SERVICE-пользователей
--    из oauth2_registered_client.created_by (по client_id = username)
-- 3. Добавляет роль ADMIN_CLIENT
-- ============================================================

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS created_by VARCHAR(50) NOT NULL DEFAULT 'system';

COMMENT ON COLUMN users.created_by
    IS 'Username пользователя, создавшего запись (admin_client/admin). system — создан при инициализации или служебным процессом.';

-- Backfill: для уже существующих SERVICE-пользователей, созданных через
-- регистрацию OAuth2-клиента, проставляем создателя клиента как владельца
UPDATE users u
SET created_by = c.created_by
FROM oauth2_registered_client c
WHERE u.user_type = 'SERVICE'
  AND u.username = c.client_id
  AND c.created_by IS NOT NULL;

-- Индекс для выборки "мои пользователи" в внешнем API
CREATE INDEX IF NOT EXISTS idx_users_created_by ON users (created_by);

-- Роль для внешних клиентов, управляющих SERVICE-пользователями через API
INSERT INTO roles (name, description, created_by)
VALUES ('ADMIN_CLIENT', 'Внешний клиент: управление своими SERVICE-пользователями через /api/auth/v1', 'system')
ON CONFLICT (name) DO NOTHING;
