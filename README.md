# Native App with KMS External Access Integration

This Snowflake Native Application sample demonstrates how to add external access integrations as references within a native application.

## Prerequisites

Install snowflake-cli
Configure it:

- Linux: ~/.config/snowflake/config.toml
- MacOS: /Applications/.../config.tom

Data Products -> Apps -> Select App -> Click Shield -> Security (Shield icon) -> Connections -> Review -> Accept

## SQL Usage

```sql
use cosmian_kms;
call cosmian_kms.core.create_eai_objects();
```
