-- Создание таблицы пользователей
CREATE TABLE IF NOT EXISTS users (
                                     id SERIAL PRIMARY KEY,
                                     username VARCHAR(50) UNIQUE NOT NULL,
                                     display_name VARCHAR(100) NOT NULL,
                                     email VARCHAR(100) UNIQUE NOT NULL,
                                     password_hash VARCHAR(255) NOT NULL,
                                     enabled BOOLEAN DEFAULT true,
                                     account_non_expired BOOLEAN DEFAULT false,
                                     account_non_locked BOOLEAN DEFAULT true,
                                     expiration_date TIMESTAMP,
                                     last_logon TIMESTAMP,
                                     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                     updated_at TIMESTAMP
);

-- Создание таблицы ролей
CREATE TABLE IF NOT EXISTS roles (
                                     id SERIAL PRIMARY KEY,
                                     name VARCHAR(50) UNIQUE NOT NULL,
                                     description TEXT,
                                     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Создание таблицы связи пользователей и ролей
CREATE TABLE IF NOT EXISTS user_roles (
                                          user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                                          role_id INTEGER REFERENCES roles(id) ON DELETE CASCADE,
                                          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                          PRIMARY KEY (user_id, role_id)
);

-- Создание таблицы ключей
CREATE TABLE IF NOT EXISTS jwks (
                                    kid UUID PRIMARY KEY,
                                    jwk_set TEXT NOT NULL,
                                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                    expiration_date TIMESTAMP NOT NULL
);

-- Вставка базовых ролей
INSERT INTO roles (name, description) VALUES
                                          ('ADMIN', 'Администратор системы'),
                                          ('USER', 'Обычный пользователь')
ON CONFLICT (name) DO NOTHING;

-- Вставка пользователя admin
INSERT INTO users (username, display_name, email, password_hash, enabled) VALUES
    ('admin', 'Администратор', 'micxem@gmail.com', '$2a$10$jIBzxTwdh4H6WR.QxatJxOLcjmJ/uWcEH9S9ikZCQ/gKGmYiy3RB2', true)
ON CONFLICT (username) DO NOTHING;

-- Вставка связи пользователя и роли
INSERT INTO user_roles (user_id, role_id) VALUES
    (1, 1)
ON CONFLICT (user_id, role_id) DO NOTHING;