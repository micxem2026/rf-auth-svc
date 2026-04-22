-- ============================================================
-- V6: Поддержка роли PERMISSION_MANAGER
--
-- 1. Добавляет created_by в таблицу roles
-- 2. Добавляет роль PERMISSION_MANAGER
-- ============================================================

-- Добавляем created_by в roles
ALTER TABLE roles
    ADD COLUMN IF NOT EXISTS created_by VARCHAR(50) NOT NULL DEFAULT 'system';

COMMENT ON COLUMN roles.created_by
    IS 'Username пользователя, создавшего роль. system — системная роль';

-- Системные роли помечаем явно
UPDATE roles
SET created_by = 'system'
WHERE name IN ('ADMIN', 'USER');

-- Добавляем роль PERMISSION_MANAGER
INSERT INTO roles (name, description, created_by)
VALUES ('PERMISSION_MANAGER', 'Управление правами для делегированных ролей', 'system')
ON CONFLICT (name) DO NOTHING;
