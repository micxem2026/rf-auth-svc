-- Добавляем столбец, если его ещё нет
ALTER TABLE IF EXISTS rightsflow.users
    ADD COLUMN IF NOT EXISTS user_type character varying(10) NOT NULL DEFAULT 'USER';

-- Добавляем CHECK-ограничение, если его ещё нет
DO $$
BEGIN
    -- Проверяем, существует ли уже ограничение с таким именем
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'chk_user_type'
    ) THEN
        -- Если не существует, создаем его
        ALTER TABLE rightsflow.users
            ADD CONSTRAINT chk_user_type
                CHECK (user_type IN ('USER', 'SERVICE'));
    END IF;
END $$;