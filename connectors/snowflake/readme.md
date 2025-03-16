---
title: 'Snowflake'
---

Snowflake connector allows querying Snowflake data warehouse.

## Config Schema

| Field | Type | Required | Description                  |
|-------|------|----------|------------------------------|
| type | string | yes | constant: `snowflake`  |
| account | string | yes | Snowflake account identifier |
| database | string | yes | Database name                |
| user | string | yes | Username                     |
| password | string | yes | Password                     |
| warehouse | string | yes | Warehouse to use for queries |
| schema | string | yes | Schema name                  |
| role | string | yes | Role to assume               |
| conn_string | string | no | Direct connection string    |

## Config example:

```yaml
type: snowflake
account: myaccount    # Your Snowflake account identifier
database: MYDB
user: myuser
password: secret
warehouse: COMPUTE_WH # Warehouse to use for queries
schema: PUBLIC        # Schema name
role: ACCOUNTADMIN    # Role to assume 
```

Or as alternative with direct connection string:

```yaml
type: snowflake
conn_string: myuser:secret@myaccount/MYDB/PUBLIC?warehouse=COMPUTE_WH&role=ACCOUNTADMIN
```
