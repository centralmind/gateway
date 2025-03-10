---
title: 'PostgreSQL'
---

PostgreSQL connector allows querying PostgreSQL databases.

## Config Schema

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| hosts | string[] | yes | List of database hosts |
| database | string | yes | Database name |
| user | string | yes | Username |
| password | string | yes | Password |
| port | integer | yes | TCP port (default 5432) |
| schema | string | no | instead of "public" it could be custom |
| tlsFile | string | no | PEM-encoded certificate for TLS |
| enableTLS | boolean | no | Enable TLS/SSL connection |

## Config example:

```yaml
type: postgres
hosts: 
  - localhost
database: mydb
user: postgres
password: secret
port: 5432
schema: sales
tlsFile: ""        # Optional PEM-encoded certificate
enableTLS: false   # Enable TLS/SSL connection 
```

## Deploy PostgreSQL Sample Databases 

 - You can deploy sample database using a docker and example of DVD store data
<a href="/example/postgresql-dvdstore-sample" /> DVDStore Sample Database</a>
