-- ============================================================
-- V5: Добавление флага защиты OAuth2 клиентов от удаления
--
-- Флаг protected = true запрещает удаление и изменение клиента
-- через веб-интерфейс. Используется для служебных клиентов
-- (system, swagger и др.), созданных администратором.
-- ============================================================

ALTER TABLE oauth2_registered_client
    ADD COLUMN IF NOT EXISTS protected BOOLEAN NOT NULL DEFAULT false;

COMMENT ON COLUMN oauth2_registered_client.protected
    IS 'Флаг защиты от удаления/изменения через веб-интерфейс';

-- Защищаем системных клиентов созданных при инициализации
UPDATE oauth2_registered_client
SET protected = true
WHERE created_by = 'system';
