# Native App with KMS External Access Integration

This Snowflake Native Application sample demonstrates how to add external access integrations as references within a native application.

## Prerequisites

Install snowflake-cli
Configure it:

- Linux: ~/.config/snowflake/config.toml
- MacOS: /Applications/.../config.tom

Data Products -> Apps -> Select App -> Click Shield -> Security (Shield icon) -> Connections -> Review -> Accept

## Enbling the external connection

Got to Data Products -> Apps
Select the `...` and `View Details`

In connections, review and approve the connection.

### Script Example
The following script describes an example of how to use the Cosmian KMS native app
and its functions.

First import the app in your worksheet, and the execute the `CREATE_EAI_OBJECT`
function to instantiate the KMS functionalities.
```sql
-- IMPORTING THE COSMIAN APP
USE COSMIAN_KMS_USERNAME;

-- CREATION OF FUNCTIONS WITH EAI RIGHTS
CALL COSMIAN_KMS_USERNAME.CORE.CREATE_EAI_OBJECTS();
```

Here we define a series of tables. The `ACCOUNTS` table is an example of data that
we want to encrypt and decrypt.
```sql
-- FOR STORING SECRETS
CREATE SCHEMA IF NOT EXISTS cosmian_integration;
CREATE TABLE IF NOT EXISTS secrets(pk VARCHAR, sk VARCHAR);
--FOR STORING DATA
CREATE SCHEMA IF NOT EXISTS DATA_DEMO;
USE SCHEMA DATA_DEMO;
CREATE TABLE IF NOT EXISTS accounts (ID INT, FIRSTNAME VARCHAR, SURNAME VARCHAR, COMPANY VARCHAR);
TRUNCATE TABLE accounts;
INSERT INTO accounts VALUES
  (1,'A1', 'B1', 'Snowflake'),
  (2,'A2', 'B2', 'Snowflake'),
  (3,'A3', 'B3', 'Snowflake'),
  (4,'A4', 'B4', 'Acme'),
  (5,'A5', 'B5', 'Snowflake'),
  (6,'A6', 'B6', 'Snowflake'),
  (7,'A7', 'B7', 'Snowflake'),
  (8,'A7', 'B8', 'Acme'),
  (9,'A9', 'B9', 'Snowflake'),
  (10,'A10', 'B10', 'Snowflake'),
  (11,'A11', 'B11', 'Snowflake'),
  (12,'A12', 'B12', 'Acme'),
  (13,'A13', 'B13', 'Snowflake'),
  (14,'A14', 'B14', 'Snowflake'),
  (15,'A15', 'B15', 'Snowflake'),
  (16,'A16', 'B16', 'Acme'),
  (17,'A17', 'B17', 'Snowflake'),
  (18,'A18', 'B18', 'Snowflake'),
  (19,'A19', 'B19', 'Snowflake'),
  (20,'A20', 'B20', 'Acme');

SELECT * FROM ACCOUNTS;
```

After, we generate keys for a user.
```sql
-- CREATING KEY PAIRS
Select COSMIAN_KMS_USERNAME.CORE.kms_create_keypair(secrets.PK) from secrets;
-- STORING KEYS
INSERT INTO secrets VALUES
 ('d9e549a9-4725-46a7-a41f-128130ad7187','9a6d08e4-da1f-4bf4-9f47-b9ee0636506c');
-- VAR ASSIGNMENT
set pk = 'd9e549a9-4725-46a7-a41f-128130ad7187';
set sk = '9a6d08e4-da1f-4bf4-9f47-b9ee0636506c';
```

Once the keys are generated, we define a table where we will insert our encrypted data.
We do this for the purposes of the tutorial.
Here follows the Encryption of the columns `FIRSTNAME` and `SURNAME`.
```sql
-- TABLE FOR STORING ENCRYPTED VALUES
CREATE TABLE IF NOT EXISTS ENC_NAME_ACCOUNTS (ID INT, FIRSTNAME VARCHAR, SURNAME VARCHAR, COMPANY VARCHAR);
SELECT * FROM ENC_NAME_ACCOUNTS;

-- INSERT ENCRYPTED VALUES
INSERT INTO ENC_NAME_ACCOUNTS
    (SELECT ID,
           COSMIAN_KMS_USERNAME.CORE.kms_encrypt($pk, FIRSTNAME),
           COSMIAN_KMS_USERNAME.CORE.kms_encrypt($pk, SURNAME),
           COMPANY
    FROM ACCOUNTS);
-- SHOW ENCRYPTED TABLE
SELECT * FROM ENC_NAME_ACCOUNTS;
```
Now the table `ENC_NAME_ACCOUNTS` has the two aforementioned columns that are encrypted.

To visualize the decrypt the two columns and see the table, execute the following
command.

```sql
-- SHOW DECRYPTED TABLE
SELECT ID,
       COSMIAN_KMS_USERNAME.CORE.kms_decrypt($sk, FIRSTNAME),
       COSMIAN_KMS_USERNAME.CORE.kms_decrypt($sk, SURNAME),
       COMPANY
FROM ENC_NAME_ACCOUNTS
ORDER BY ID;
```
