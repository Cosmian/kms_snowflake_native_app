-- 1. Create application roles
CREATE APPLICATION ROLE IF NOT EXISTS app_public;

-- 2. Create a versioned schema to hold those UDFs/Stored Procedures
CREATE OR ALTER VERSIONED SCHEMA core;
GRANT USAGE ON SCHEMA core TO APPLICATION ROLE app_public;
CREATE SCHEMA IF NOT EXISTS public;
GRANT USAGE ON SCHEMA public TO APPLICATION ROLE app_public;

-- 3. Create callbacks called in the manifest.yml
CREATE OR REPLACE PROCEDURE core.register_single_callback(ref_name STRING, operation STRING, ref_or_alias STRING)
    RETURNS STRING
    LANGUAGE SQL
AS
$$
BEGIN
CASE (operation)
    WHEN 'ADD' THEN
        SELECT SYSTEM$SET_REFERENCE(:ref_name, :ref_or_alias);
    WHEN 'REMOVE' THEN
        SELECT SYSTEM$REMOVE_REFERENCE(:ref_name);
    WHEN 'CLEAR' THEN
        SELECT SYSTEM$REMOVE_REFERENCE(:ref_name);
    ELSE RETURN 'unknown operation: ' || operation;
    END
CASE;
END;
$$;

GRANT USAGE ON PROCEDURE core.register_single_callback(STRING, STRING, STRING) TO APPLICATION ROLE app_public;

-- Configuration callback for the `EXTERNAL_ACCESS_REFERENCE` defined in the manifest.yml
-- The procedure returns a json format object containing information about the EAI to be created, that is
-- and show the same information in a popup-window in the UI.
-- There are no allowed_secrets since the API doesn't require authentication.
CREATE OR REPLACE PROCEDURE core.get_configuration(ref_name STRING)
    RETURNS STRING
    LANGUAGE SQL
AS
$$
BEGIN
CASE (UPPER(ref_name))
    WHEN 'EXTERNAL_ACCESS_REFERENCE' THEN RETURN OBJECT_CONSTRUCT(
                'type', 'CONFIGURATION',
                'payload', OBJECT_CONSTRUCT(
                        'host_ports', ARRAY_CONSTRUCT('kms-snowflake-test.cosmian.dev:443'),
                        'allowed_secrets', 'NONE')
                         )::STRING;
    ELSE RETURN '';
END
CASE;
END;
$$;

GRANT USAGE ON PROCEDURE core.get_configuration (STRING) TO APPLICATION ROLE app_public;

--  4. Create stored procedures using the external access reference from the manifest.yml
-- The Stored Procedures needs to be created in runtime because EAI reference needs to be set
-- after installing the application.
CREATE OR REPLACE PROCEDURE core.create_eai_objects()
    RETURNS STRING
    LANGUAGE SQL
AS
$$
BEGIN
    -- 
    -- AES GCM
    --

    CREATE OR REPLACE FUNCTION core.encrypt_aes_gcm(key VARCHAR, plaintext BINARY)
        RETURNS BINARY
        LANGUAGE PYTHON
        VOLATILE 
        RUNTIME_VERSION = '3.11'
        IMPORTS = (
           '/module-api/client_configuration.py',
           '/module-api/cosmian_kms.py',
           '/module-api/initialize.py',
           '/module-api/lru_cache.py',
           '/module-api/session.py',
           '/module-api/bulk_data.py',
           '/module-api/op_shared.py',
           '/module-api/op_encrypt.py',
           '/module-api/op_decrypt.py',
           '/module-api/kmip_shared.py',
           '/module-api/kmip_decrypt.py',
           '/module-api/kmip_encrypt.py',
           '/module-api/kmip_post.py'
        )
        PACKAGES = (
            'leb128',
            'orjson',
            'pandas',
            'requests',
            'snowflake-snowpark-python',
            'typing',
            'python-xxhash'
        )
        HANDLER = 'cosmian_kms.encrypt_aes_gcm'
        EXTERNAL_ACCESS_INTEGRATIONS = (reference('EXTERNAL_ACCESS_REFERENCE'));

    GRANT USAGE ON FUNCTION core.encrypt_aes_gcm(VARCHAR,BINARY) TO APPLICATION ROLE app_public;
                                                

    CREATE OR REPLACE FUNCTION core.decrypt_aes_gcm(key VARCHAR, ciphertext BINARY)
        RETURNS BINARY
        LANGUAGE PYTHON
        VOLATILE
        RUNTIME_VERSION = '3.11'
        IMPORTS = (
           '/module-api/client_configuration.py',
           '/module-api/cosmian_kms.py',
           '/module-api/initialize.py',
           '/module-api/lru_cache.py',
           '/module-api/session.py',
           '/module-api/bulk_data.py',
           '/module-api/op_shared.py',
           '/module-api/op_encrypt.py',
           '/module-api/op_decrypt.py',
           '/module-api/kmip_shared.py',
           '/module-api/kmip_decrypt.py',
           '/module-api/kmip_encrypt.py',
           '/module-api/kmip_post.py'
        )
        PACKAGES = (
            'leb128',
            'orjson',
            'pandas',
            'requests',
            'snowflake-snowpark-python',
            'typing',
            'python-xxhash'
        )
        HANDLER = 'cosmian_kms.decrypt_aes_gcm'
        EXTERNAL_ACCESS_INTEGRATIONS = (reference('EXTERNAL_ACCESS_REFERENCE'));

    GRANT USAGE ON FUNCTION core.decrypt_aes_gcm (VARCHAR,BINARY) TO APPLICATION ROLE app_public;


    -- 
    -- AES GCM SIV
    --

    CREATE OR REPLACE FUNCTION core.encrypt_aes_gcm_siv(key VARCHAR, nonce VARCHAR, plaintext BINARY)
        RETURNS BINARY
        LANGUAGE PYTHON
        IMMUTABLE
        RUNTIME_VERSION = '3.11'
        IMPORTS = (
           '/module-api/client_configuration.py',
           '/module-api/cosmian_kms.py',
           '/module-api/initialize.py',
           '/module-api/lru_cache.py',
           '/module-api/session.py',
           '/module-api/bulk_data.py',
           '/module-api/op_shared.py',
           '/module-api/op_encrypt.py',
           '/module-api/op_decrypt.py',
           '/module-api/kmip_shared.py',
           '/module-api/kmip_decrypt.py',
           '/module-api/kmip_encrypt.py',
           '/module-api/kmip_post.py'
        )
        PACKAGES = (
            'leb128',
            'orjson',
            'pandas',
            'requests',
            'snowflake-snowpark-python',
            'typing',
            'python-xxhash'
        )
        HANDLER = 'cosmian_kms.encrypt_aes_gcm_siv'
        EXTERNAL_ACCESS_INTEGRATIONS = (reference('EXTERNAL_ACCESS_REFERENCE'));

    GRANT USAGE ON FUNCTION core.encrypt_aes_gcm_siv (VARCHAR,VARCHAR,BINARY) TO APPLICATION ROLE app_public;

    CREATE OR REPLACE FUNCTION core.decrypt_aes_gcm_siv(key VARCHAR, nonce VARCHAR, ciphertext BINARY)
        RETURNS BINARY
        LANGUAGE PYTHON
        IMMUTABLE
        RUNTIME_VERSION = '3.11'
        IMPORTS = (
           '/module-api/client_configuration.py',
           '/module-api/cosmian_kms.py',
           '/module-api/initialize.py',
           '/module-api/lru_cache.py',
           '/module-api/session.py',
           '/module-api/bulk_data.py',
           '/module-api/op_shared.py',
           '/module-api/op_encrypt.py',
           '/module-api/op_decrypt.py',
           '/module-api/kmip_shared.py',
           '/module-api/kmip_decrypt.py',
           '/module-api/kmip_encrypt.py',
           '/module-api/kmip_post.py'
        )
        PACKAGES = (
            'leb128',
            'orjson',
            'pandas',
            'requests',
            'snowflake-snowpark-python',
            'typing',
            'python-xxhash'
        )
        HANDLER = 'cosmian_kms.decrypt_aes_gcm_siv'
        EXTERNAL_ACCESS_INTEGRATIONS = (reference('EXTERNAL_ACCESS_REFERENCE'));

    GRANT USAGE ON FUNCTION core.decrypt_aes_gcm_siv (VARCHAR,VARCHAR,BINARY) TO APPLICATION ROLE app_public;


    -- 
    -- AES XTS
    --

    CREATE OR REPLACE FUNCTION core.encrypt_aes_xts(key VARCHAR, plaintext BINARY)
        RETURNS BINARY
        LANGUAGE PYTHON
        VOLATILE
        RUNTIME_VERSION = '3.11'
        IMPORTS = (
           '/module-api/client_configuration.py',
           '/module-api/cosmian_kms.py',
           '/module-api/initialize.py',
           '/module-api/lru_cache.py',
           '/module-api/session.py',
           '/module-api/bulk_data.py',
           '/module-api/op_shared.py',
           '/module-api/op_encrypt.py',
           '/module-api/op_decrypt.py',
           '/module-api/kmip_shared.py',
           '/module-api/kmip_decrypt.py',
           '/module-api/kmip_encrypt.py',
           '/module-api/kmip_post.py'
        )
        PACKAGES = (
            'leb128',
            'orjson',
            'pandas',
            'requests',
            'snowflake-snowpark-python',
            'typing',
            'python-xxhash'
        )
        HANDLER = 'cosmian_kms.encrypt_aes_xts'
        EXTERNAL_ACCESS_INTEGRATIONS = (reference('EXTERNAL_ACCESS_REFERENCE'));

    GRANT USAGE ON FUNCTION core.encrypt_aes_xts (VARCHAR,BINARY) TO APPLICATION ROLE app_public;

    CREATE OR REPLACE FUNCTION core.decrypt_aes_xts(key VARCHAR, ciphertext BINARY)
        RETURNS BINARY
        LANGUAGE PYTHON
        IMMUTABLE
        RUNTIME_VERSION = '3.11'
        IMPORTS = (
           '/module-api/client_configuration.py',
           '/module-api/cosmian_kms.py',
           '/module-api/initialize.py',
           '/module-api/lru_cache.py',
           '/module-api/session.py',
           '/module-api/bulk_data.py',
           '/module-api/op_shared.py',
           '/module-api/op_encrypt.py',
           '/module-api/op_decrypt.py',
           '/module-api/kmip_shared.py',
           '/module-api/kmip_decrypt.py',
           '/module-api/kmip_encrypt.py',
           '/module-api/kmip_post.py'
        )
        PACKAGES = (
            'leb128',
            'orjson',
            'pandas',
            'requests',
            'snowflake-snowpark-python',
            'typing',
            'python-xxhash'
        )
        HANDLER = 'cosmian_kms.decrypt_aes_xts'
        EXTERNAL_ACCESS_INTEGRATIONS = (reference('EXTERNAL_ACCESS_REFERENCE'));

    GRANT USAGE ON FUNCTION core.decrypt_aes_xts (VARCHAR,BINARY) TO APPLICATION ROLE app_public;


    -- 
    -- ChaCha20 Poly1305
    --

    CREATE OR REPLACE FUNCTION core.encrypt_chacha20_poly1305(key VARCHAR, plaintext BINARY)
        RETURNS BINARY
        LANGUAGE PYTHON
        VOLATILE
        RUNTIME_VERSION = '3.11'
        IMPORTS = (
           '/module-api/client_configuration.py',
           '/module-api/cosmian_kms.py',
           '/module-api/initialize.py',
           '/module-api/lru_cache.py',
           '/module-api/session.py',
           '/module-api/bulk_data.py',
           '/module-api/op_shared.py',
           '/module-api/op_encrypt.py',
           '/module-api/op_decrypt.py',
           '/module-api/kmip_shared.py',
           '/module-api/kmip_decrypt.py',
           '/module-api/kmip_encrypt.py',
           '/module-api/kmip_post.py'
        )
        PACKAGES = (
            'leb128',
            'orjson',
            'pandas',
            'requests',
            'snowflake-snowpark-python',
            'typing',
            'python-xxhash'
        )
        HANDLER = 'cosmian_kms.encrypt_chacha20_poly1305'
        EXTERNAL_ACCESS_INTEGRATIONS = (reference('EXTERNAL_ACCESS_REFERENCE'));

    GRANT USAGE ON FUNCTION core.encrypt_chacha20_poly1305 (VARCHAR,BINARY) TO APPLICATION ROLE app_public;

    CREATE OR REPLACE FUNCTION core.decrypt_chacha20_poly1305(key VARCHAR, ciphertext BINARY)
        RETURNS BINARY
        LANGUAGE PYTHON
        IMMUTABLE
        RUNTIME_VERSION = '3.11'
        IMPORTS = (
           '/module-api/client_configuration.py',
           '/module-api/cosmian_kms.py',
           '/module-api/initialize.py',
           '/module-api/lru_cache.py',
           '/module-api/session.py',
           '/module-api/bulk_data.py',
           '/module-api/op_shared.py',
           '/module-api/op_encrypt.py',
           '/module-api/op_decrypt.py',
           '/module-api/kmip_shared.py',
           '/module-api/kmip_decrypt.py',
           '/module-api/kmip_encrypt.py',
           '/module-api/kmip_post.py'
        )
        PACKAGES = (
            'leb128',
            'orjson',
            'pandas',
            'requests',
            'snowflake-snowpark-python',
            'typing',
            'python-xxhash'
        )
        HANDLER = 'cosmian_kms.decrypt_chacha20_poly1305'
        EXTERNAL_ACCESS_INTEGRATIONS = (reference('EXTERNAL_ACCESS_REFERENCE'));

    GRANT USAGE ON FUNCTION core.decrypt_chacha20_poly1305 (VARCHAR,BINARY) TO APPLICATION ROLE app_public;

RETURN 'SUCCESS';
END;
$$;

GRANT USAGE ON PROCEDURE core.create_eai_objects() TO APPLICATION ROLE app_public;



-- 5. Create a streamlit object using the code you wrote in you wrote in src/module-ui, as shown below.
-- The `from` value is derived from the stage path described in snowflake.yml
-- CREATE STREAMLIT core.ui
--      FROM '/streamlit/'
--      MAIN_FILE = 'ui.py';

-- 6. Grant appropriate privileges over these objects to your application roles.
-- GRANT USAGE ON STREAMLIT core.ui TO APPLICATION ROLE app_public;

-- A detailed explanation can be found at https://docs.snowflake.com/en/developer-guide/native-apps/adding-streamlit