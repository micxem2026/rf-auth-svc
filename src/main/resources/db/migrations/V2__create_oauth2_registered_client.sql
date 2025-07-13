-- Создание таблицы для зарегистрированных OAuth2 клиентов
CREATE TABLE oauth2_registered_client (
                                          id varchar(100) NOT NULL,
                                          client_id varchar(100) NOT NULL,
                                          client_id_issued_at timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
                                          client_secret varchar(200) DEFAULT NULL,
                                          client_secret_expires_at timestamp DEFAULT NULL,
                                          client_name varchar(200) NOT NULL,
                                          client_authentication_methods varchar(1000) NOT NULL,
                                          authorization_grant_types varchar(1000) NOT NULL,
                                          redirect_uris varchar(1000) DEFAULT NULL,
                                          post_logout_redirect_uris varchar(1000) DEFAULT NULL,
                                          scopes varchar(1000) NOT NULL,
                                          client_settings varchar(2000) NOT NULL,
                                          token_settings varchar(2000) NOT NULL,
                                          created_by varchar(50) NOT NULL,
                                          created_at timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
                                          updated_at timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
                                          PRIMARY KEY (id)
);

CREATE UNIQUE INDEX oauth2_registered_client_client_id_idx ON oauth2_registered_client (client_id);

-- Добавляем системного клиента svcClient в базу данных
INSERT INTO oauth2_registered_client (
    id, client_id, client_secret, client_name,
    client_authentication_methods, authorization_grant_types,
    scopes, client_settings, token_settings, created_by
) VALUES (
             'system-svc-client-id',
             'svc-client',
             '$2a$10$PF4SCvOpUMba.p2Mx2bL/e/3ldyZMq70.VgO.bq.DtjoTx8PFj5j.',
             'System Service Client',
             'client_secret_basic',
             'client_credentials,client_registration',
             'read,update,execute,delete,create,client.create,client.read',
             '{"@class":"java.util.Map","settings.client.require-authorization-consent":false,"settings.client.require-proof-key":false}',
             '{"@class":"java.util.Map","settings.token.access-token-time-to-live":["java.time.Duration",3600.000000000],"settings.token.refresh-token-time-to-live":["java.time.Duration",2592000.000000000],"settings.token.reuse-refresh-tokens":true}',
             'system'
         );

-- Добавляем spa-client в базу данных
INSERT INTO oauth2_registered_client (
    id, client_id, client_secret, client_name,
    client_authentication_methods, authorization_grant_types,
    redirect_uris, scopes, client_settings, token_settings, created_by
) VALUES (
             'system-spa-client-id',
             'spa-client',
             '$2a$10$K9CrnOBK41aJMDFMMc.teeVpq1tg1IclkyCOUKvlOzKey1XPUVV0m',
             'Single Page Application Client',
             'client_secret_basic',
             'authorization_code,refresh_token',
             'http://localhost:9000/callback',
             'openid,profile,read,update,execute,delete,create',
             '{"@class":"java.util.Map","settings.client.require-authorization-consent":false,"settings.client.require-proof-key":false}',
             '{"@class":"java.util.Map","settings.token.access-token-time-to-live":["java.time.Duration",3600.000000000],"settings.token.refresh-token-time-to-live":["java.time.Duration",2592000.000000000],"settings.token.reuse-refresh-tokens":true}',
             'system'
         );
