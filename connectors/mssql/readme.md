---
title: 'Microsoft SQL Server'
---

Microsoft SQL Server connector allows querying SQL Server and Azure SQL databases.

## Config Schema

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| type | string | yes | constant: `mssql` |
| hosts | string[] | yes | List of server addresses (e.g., ["localhost", "**.database.windows.net"]) |
| user | string | yes | Username for SQL Server Authentication |
| password | string | yes | Password for SQL Server Authentication |
| database | string | yes | Database name |
| port | integer | no | Port number (default: 1433) |
| schema | string | no | Schema name (default: "dbo") |
| conn_string | string | no | Direct connection string |

## Config example:

```yaml
type: mssql
hosts:
  - my-server.database.windows.net 
user: my_user
password: my_password
database: my_database
port: 1433
schema: dbo
```

Or as alternative with direct connection string:

```yaml
type: mssql
conn_string: sqlserver://my_user:my_password@my-server.database.windows.net:1433?database=my_database&schema=dbo
```

## Notes

- The connector uses the first host in the list by default. Additional hosts can be specified for future failover implementation.
- When using Azure SQL Database, make sure to use the full server name (*.database.windows.net).
- The schema parameter defaults to "dbo" if not specified.
- For named instances, include the instance name in the host: `server\instance`.
- SQL Server authentication is used for connections. Windows authentication is not currently supported. 