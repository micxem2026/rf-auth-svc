-- ============================================================
-- V4: Система управления правами доступа (permissions)
--
-- Добавляет:
--   permissions      — справочник прав (сервис:ресурс:действие)
--   role_permissions — связь роль → права
-- ============================================================

-- Таблица прав доступа
-- Право идентифицируется тройкой (service, resource, action).
-- service  = spring.application.name микросервиса (например, rf-contract-svc)
-- resource = имя контроллера                      (например, ContractController)
-- action   = имя метода контроллера               (например, createContract)
CREATE TABLE IF NOT EXISTS permissions (
    id          SERIAL PRIMARY KEY,
    service     VARCHAR(100) NOT NULL,
    resource    VARCHAR(100) NOT NULL,
    action      VARCHAR(100) NOT NULL,
    description TEXT,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Уникальность тройки гарантирует отсутствие дублей
    CONSTRAINT uq_permissions_service_resource_action
        UNIQUE (service, resource, action)
);

COMMENT ON TABLE  permissions          IS 'Справочник прав доступа к методам микросервисов';
COMMENT ON COLUMN permissions.service  IS 'Имя микросервиса (spring.application.name)';
COMMENT ON COLUMN permissions.resource IS 'Имя контроллера (например ContractController)';
COMMENT ON COLUMN permissions.action   IS 'Имя метода контроллера (например createContract)';

-- Индекс для быстрой выборки всех прав конкретного сервиса
-- (используется при загрузке кэша микросервисом)
CREATE INDEX IF NOT EXISTS idx_permissions_service
    ON permissions (service);

-- Индекс для быстрой выборки прав конкретного сервиса+ресурса
CREATE INDEX IF NOT EXISTS idx_permissions_service_resource
    ON permissions (service, resource);

-- ============================================================

-- Таблица связи роль → права
-- Одна роль может иметь множество прав.
-- Одно право может быть назначено множеству ролей.
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id       INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id INTEGER NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    granted_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    granted_by    VARCHAR(50),        -- username администратора, назначившего право
    PRIMARY KEY (role_id, permission_id)
);

COMMENT ON TABLE  role_permissions            IS 'Права, назначенные ролям';
COMMENT ON COLUMN role_permissions.granted_by IS 'Username администратора, назначившего право';

-- Индекс для обратного поиска: какие роли имеют данное право
CREATE INDEX IF NOT EXISTS idx_role_permissions_permission_id
    ON role_permissions (permission_id);

INSERT INTO roles (name, description, created_by)
VALUES ('SERVICE', 'Системная роль для межсервисного взаимодействия', 'system')
ON CONFLICT (name) DO NOTHING;

INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id
FROM users u, roles r
WHERE u.username = 'system'
  AND r.name = 'SERVICE'
ON CONFLICT DO NOTHING;

-- ============================================================
-- Начальные данные: права для системных ролей ADMIN и USER
-- Права описывают веб-интерфейс rf-auth-svc
-- ============================================================

-- Права для управления пользователями (AdminUserController)
/*
INSERT INTO permissions (service, resource, action, description) VALUES
    ('rf-auth-svc', 'AdminUserController', 'getAllUsers', 'Получение списка всех пользователей'),
    ('rf-auth-svc', 'AdminUserController', 'getUserById', 'Получение пользователя по ID'),
    ('rf-auth-svc', 'AdminUserController', 'createUser',  'Создание нового пользователя'),
    ('rf-auth-svc', 'AdminUserController', 'updateUser',  'Редактирование пользователя'),
    ('rf-auth-svc', 'AdminUserController', 'deleteUser',  'Удаление пользователя'),
    ('rf-auth-svc', 'AdminUserController', 'getAllRoles', 'Получение списка ролей'),
    ('rf-auth-svc', 'AdminUserController', 'createRole',  'Создание новой роли'),
    ('rf-auth-svc', 'AdminUserController', 'deleteRole',  'Удаление роли')
ON CONFLICT ON CONSTRAINT uq_permissions_service_resource_action DO NOTHING;
*/
-- Права для управления OAuth2 клиентами (ClientRegistrationController)
/*
INSERT INTO permissions (service, resource, action, description) VALUES
    ('rf-auth-svc', 'ClientRegistrationController', 'registerClient', 'Регистрация OAuth2 клиента'),
    ('rf-auth-svc', 'ClientRegistrationController', 'getClients',     'Получение списка клиентов'),
    ('rf-auth-svc', 'ClientRegistrationController', 'getClient',      'Получение клиента по ID'),
    ('rf-auth-svc', 'ClientRegistrationController', 'updateClient',   'Редактирование клиента'),
    ('rf-auth-svc', 'ClientRegistrationController', 'deleteClient',   'Удаление клиента')
ON CONFLICT ON CONSTRAINT uq_permissions_service_resource_action DO NOTHING;
*/
-- Права для управления правами (PermissionController — будет создан)
/*
INSERT INTO permissions (service, resource, action, description) VALUES
    ('rf-auth-svc', 'PermissionController', 'getAllPermissions',      'Получение списка всех прав'),
    ('rf-auth-svc', 'PermissionController', 'getPermissionsByService','Получение прав по сервису'),
    ('rf-auth-svc', 'PermissionController', 'createPermission',       'Создание нового права'),
    ('rf-auth-svc', 'PermissionController', 'deletePermission',       'Удаление права'),
    ('rf-auth-svc', 'PermissionController', 'getRolePermissions',     'Получение прав роли'),
    ('rf-auth-svc', 'PermissionController', 'assignPermission',       'Назначение права роли'),
    ('rf-auth-svc', 'PermissionController', 'revokePermission',       'Снятие права с роли'),
    ('rf-auth-svc', 'PermissionController', 'getPermissionsByRoles',  'Загрузка прав для кэша (для микросервисов)')
ON CONFLICT ON CONSTRAINT uq_permissions_service_resource_action DO NOTHING;
*/
-- ============================================================
-- Назначаем роли ADMIN все права rf-auth-svc
-- ============================================================
/*
INSERT INTO role_permissions (role_id, permission_id, granted_by)
SELECT
    r.id,
    p.id,
    'system'
FROM roles r
         CROSS JOIN permissions p
WHERE r.name = 'ADMIN'
  AND p.service = 'rf-auth-svc'
ON CONFLICT (role_id, permission_id) DO NOTHING;
*/