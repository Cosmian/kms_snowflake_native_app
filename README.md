<h1>snowflake connector for Cosmian KMS</h1>

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

