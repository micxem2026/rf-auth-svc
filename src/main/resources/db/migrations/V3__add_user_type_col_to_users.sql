ALTER TABLE IF EXISTS rightsflow.users
    ADD COLUMN user_type character varying(10) NOT NULL DEFAULT 'USER';

ALTER TABLE IF EXISTS rightsflow.users
    ADD CONSTRAINT chk_user_type CHECK (user_type in ('USER','SERVICE'))
    NOT VALID;