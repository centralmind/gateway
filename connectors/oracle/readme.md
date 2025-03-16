---
title: 'Oracle Database'
---

Oracle Database connector allows querying Oracle databases using pure Go implementation without requiring Oracle Instant Client.

## Config Schema

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| type | string | yes | constant: `oracle` |
| hosts | string[] | yes | List of server addresses (e.g., ["localhost", "oracle.example.com"]) |
| user | string | yes | Username for database authentication |
| password | string | yes | Password for database authentication |
| database | string | yes | Service name or SID |
| schema | string | yes | Schema name (e.g., "HR", "SYSTEM") |
| port | integer | yes | Port number (default: 1521) |
| conn_string | string | no | Direct connection string |

## Config example:

```yaml
type: oracle
hosts:
  - localhost
user: system
password: secretpassword
database: FREEPDB1
schema: HR
port: 1521
```

Or as alternative with direct connection string:

```yaml
type: oracle
conn_string: oracle://system:secretpassword@localhost:1521/FREEPDB1
```

## Notes

- The connector uses the first host in the list by default. Additional hosts can be specified for future failover implementation.
- The schema parameter is required and specifies the default schema for queries.
- The database parameter should be your Oracle service name or SID.
- The connector uses <a href="https://github.com/sijms/go-ora">go-ora driver</a> which is a pure Go implementation, no Oracle Instant Client required.
- When using named parameters in queries, they will be automatically converted to numbered parameters (`:1`, `:2`, etc.) as required by Oracle.
- For pagination, use Oracle's `OFFSET ... ROWS FETCH NEXT ... ROWS ONLY` syntax. 