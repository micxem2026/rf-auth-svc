-- Добавляем столбец, если его ещё нет
ALTER TABLE IF EXISTS rightsflow.users
    ADD COLUMN IF NOT EXISTS user_type character varying(10) NOT NULL DEFAULT 'USER';

-- Добавляем CHECK-ограничение, если его ещё нет
ALTER TABLE IF EXISTS rightsflow.users
    ADD CONSTRAINT IF NOT EXISTS chk_user_type
    CHECK (user_type IN ('USER', 'SERVICE'))
    NOT VALID;