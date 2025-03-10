---
title: 'MySQL'
---

MySQL connector allows querying MySQL/MariaDB databases.

## Config Schema

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| host | string | yes | Database host address |
| database | string | yes | Database name |
| user | string | yes | Username |
| password | string | yes | Password |
| port | integer | yes | TCP port (default 3306) |
| tlsConfig | string | no | TLS configuration name from MySQL server |

## Config example:

```yaml
type: mysql
host: localhost
database: mydb
user: root
password: secret
port: 3306
tlsConfig: ""       # Optional TLS configuration name from MySQL server 
```
