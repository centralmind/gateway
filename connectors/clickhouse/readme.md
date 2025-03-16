---
title: 'Clickhouse'
---

ClickHouse connector allows querying ClickHouse databases.


## Config Schema

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| type | string | yes | constant: `clickhouse`  |
| host | string | no | Single host address |
| hosts | string[] | no | Multiple hosts for cluster setup |
| database | string | yes | Database name |
| user | string | yes | Username |
| password | string | yes | Password |
| port | integer | yes | HTTP port (default 8123) |
| secure | boolean | no | Use HTTPS instead of HTTP |
| conn_string | string | no | Direct connection string |

## Config example:

```yaml
type: clickhouse
host: localhost      # Single host address
hosts:              # Or multiple hosts for cluster setup
  - host1.example.com
  - host2.example.com
database: mydb
user: default
password: secret
port: 8123
secure: false       # Use HTTPS instead of HTTP 
```

Or as alternative with direct connection string:

```yaml
type: clickhouse
conn_string: http://default:secret@localhost:8123/mydb
```
