---
title: 'DuckDB'
---

DuckDB connector allows querying DuckDB databases, which is an embedded analytical database similar to SQLite but optimized for OLAP workloads.

## Config Schema

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| type | string | yes | constant: `duckdb` |
| hosts | string[] | no* | List of paths (only first path is used) |
| database | string | no* | Database file name, will be opened in readonly mode |




## Config Examples

1. Using directory path in hosts:
```yaml
connection:
  type: duckdb
  hosts:
    - ./data    # relative path to directory
  database: analytics.duckdb
```

2. Using full file path in hosts:
```yaml
connection:
  type: duckdb
  hosts:
    - /absolute/path/to/analytics.duckdb    # Unix-style path
    # or
    - C:/Users/MyUser/data/analytics.duckdb  # Windows-style path
```

3. Using relative file path:
```yaml
connection:
  type: duckdb
  hosts:
    - ./data/analytics.duckdb
```

4. Using current directory:
```yaml
connection:
  type: duckdb
  hosts:
    - .
  database: analytics.duckdb
```

5. Using in-memory mode, just leave connection section blank:
```yaml
connection:

```
6. Using in-memory mode, or just put ":memory:":
```yaml
connection: ":memory:"
  
```

## Running Discovery and API
You can also pass connection string as parameter, eg using absolute path on Linux:
```
./gateway discover --ai-provider gemin --connection-string "duckdb:///absolute/path/to/duckdb-demo.duckdb"
```
or on Windows
```
.\gateway discover --ai-provider gemini --connection-string  "duckdb://C:/path/duckdb-demo.duckdb"
```

Start server, it will use `gateway.yaml` generated from prev step:
```
./gateway start
```


## Path Resolution

The final database path is determined as follows:
1. If `hosts[0]` and `database` are provided: `hosts[0]/database`
2. If only `hosts[0]` is provided: uses it as the complete path
3. If only `database` is provided: uses it as a local path


## Notes

- DuckDB is an embedded database, so no server setup is required
- Only the first path in `hosts` is used (others are ignored)
- Both forward slashes `/` and backslashes `\` are supported for Windows paths
- Relative paths are resolved relative to the current working directory
- Database works only in Read-only mode
