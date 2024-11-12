# Cosmian KMS Integration


This native app lets you perform encryption and decryption operations in snowflake queries using Cosmian KMS.

Example: query the CUSTOMERS table where the customer `name` is encrypted in the database and you want to decrypt it in
the query.

```sql
SELECT id, decrypt_aes_gcm($KEY_ID, name) AS name
FROM CUSTOMERS;
```

where `$KEY_ID` is the AES key identifier in Cosmian KMS.

The native app exposes vectorized User Defined Functions (UDFs) to perform encryption and decryption operations with
the following protocols :

- AES-GCM (NIST SP 800-38D)
- AES GCM SIV (RFC 8452)
- AES XTS (NIST SP 800-38E)
- ChCha20-Poly1305 (RFC 8439)

## Setup

### Prerequisites

Install snowflake-cli and configure a connection to your Snowflake account.

### Deploy the cosmian_kms_app

```bash
snow app run -c <connection_name> --warehouse <warehouse_name>
```

### Enable the external connection

Go to Data Products -> Apps
Select the `...` and `View Details`

In connections, review and approve the connection.

### Deploy the User Defined Functions

The external connection must be approved before deploying the UDFs.

```bash
snow sql -q "CALL COSMIAN_KMS_APP.CORE.CREATE_EAI_OBJECTS()" -c <connection_name>
```

## Using the UDFs

You must use the `COSMIAN_KMS_APP` schema to access the UDFs.

```snowflake
USE COSMIAN_KMS_APP;
```

Let us create a schema to store tests tables.

```snowflake
CREATE SCHEMA COSMIAN_KMS_APP.ENCRYPTION_TESTS;
```

Wwe are going to create a table with encrypted data with 5Mn lines of the `CUSTOMER` table from the
`SNOWFLAKE_SAMPLE_DATA.TPCH_SF1000` schema.
Before doing so, you must create an AES key in the KMS;
say the key id is `0d319307-f766-4869-b90a-02096edb9431`.

```snowflake
CREATE OR REPLACE TABLE COSMIAN_KMS_APP.ENCRYPTION_TESTS.CUSTOMER_ENCRYPTED AS
SELECT C_CUSTKEY,
       C_NAME,
       cosmian_kms_app.core.encrypt_aes('0d319307-f766-4869-b90a-02096edb9431',
                                        TO_BINARY(C_NAME, 'UTF-8')) AS C_NAME_ENCRYPTED,
       C_PHONE
FROM SNOWFLAKE_SAMPLE_DATA.TPCH_SF1000.CUSTOMER
LIMIT 5000000;
```

Now we are going to create a table with the decrypted data.

```snowflake
CREATE OR REPLACE TABLE COSMIAN_KMS_APP.ENCRYPTION_TESTS.CUSTOMER_DECRYPTED AS
SELECT C_CUSTKEY,
       C_NAME,
       cosmian_kms_app.core.decrypt_aes('0d319307-f766-4869-b90a-02096edb9431', C_NAME_ENCRYPTED) AS C_NAME_DECRYPTED,
       C_PHONE
FROM COSMIAN_KMS_APP.ENCRYPTION_TESTS.CUSTOMER_ENCRYPTED;
```

## Logging

The app logs are available from `SNOWFLAKE.TELEMETRY.EVENTS`.

```snowflake
-- Set the logging level to DEBUG for the current session.
ALTER SESSION SET LOG_LEVEL = DEBUG;

SELECT TIMESTAMP, RECORD, RECORD_ATTRIBUTES, VALUE FROM SNOWFLAKE.TELEMETRY.EVENTS 
    -- WHERE SCOPE=OBJECT_CONSTRUCT('name', 'kms_decrypt')
    ORDER BY TIMESTAMP DESC 
    LIMIT 1000;
```
