---
title: 'MongoDB'
---

MongoDB connector allows querying MongoDB databases using their native query language.

## Config Schema

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| type | string | yes | constant: `mongodb` |
| hosts | string[] | yes | List of MongoDB hosts (e.g., ["localhost:27017"]) |
| database | string | yes | Database name |
| username | string | yes | Username for authentication |
| password | string | yes | Password for authentication |
| is_readonly | boolean | no | Whether to open database in read-only mode |
| conn_string | string | no | Direct connection string |

## Config example:

```yaml
connection:
    type: mongodb
    hosts:
    - localhost:27017
    - mongodb-node2:27017
    database: mydb
    username: admin
    password: secret
    is_readonly: false
```

Or as alternative with direct connection string:

```yaml
connection:
    type: mongodb
    conn_string: mongodb://admin:secret@localhost:27017/mydb
```

## Query Format

MongoDB queries must be written in JSON format with the following structure:

```json
{
    "collection": "users",
    "filter": {
        "age": {"$gt": "@minAge"},
        "status": "@status"
    }
}
```

### Query Parameters

- Use `@paramName` syntax for parameter substitution
- Parameters are automatically replaced with their values
- Supports all MongoDB query operators (`$gt`, `$lt`, `$in`, etc.)

### Pagination

For pagination, use MongoDB's native operators:
- `skip`: Number of documents to skip
- `limit`: Maximum number of documents to return

Example with pagination:
```json
{
    "collection": "users",
    "filter": {
        "status": "@status"
    },
    "skip": "@offset",
    "limit": "@limit"
}
```

## Notes

- The connector uses the official MongoDB Go driver
- For high availability, specify multiple hosts - the client will automatically handle failover
- Authentication is required for all connections
- The database parameter is required and specifies the default database for queries
- Supports MongoDB version 4.0 and above
- Queries are executed using MongoDB's native query language
- Schema discovery is based on sample documents from collections
