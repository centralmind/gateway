# Database Connection Examples

This directory contains examples of various databases running in Docker containers with test data.

## Connection Strings

### PostgreSQL
```
postgresql://postgres:postgres@localhost:35432/testdb
```

### MySQL
```
mysql://user:password@localhost:33306/testdb
```

### MSSQL
```
sqlserver://sa:YourStrong@Passw0rd@localhost:31433?database=testdb
```

### ClickHouse
```
tcp://clickhouse:password@localhost:39000/testdb
```

## Ports

- PostgreSQL: 35432
- MySQL: 33306
- MSSQL: 31433
- ClickHouse: 
  - HTTP: 38123
  - Native: 39000

## Credentials

### PostgreSQL
- User: postgres
- Password: postgres
- Database: testdb

### MySQL
- User: user
- Password: password
- Database: testdb
- Root Password: root

### MSSQL
- User: sa
- Password: YourStrong@Passw0rd
- Database: testdb

### ClickHouse
- User: clickhouse
- Password: password
- Database: testdb

## Running

To start all databases:

```bash
docker-compose up -d
```

To stop all databases:

```bash
docker-compose down
```

## Test Data

Each database is initialized with test data from the corresponding connector's test files:
- PostgreSQL: `../connectors/postgres/testdata/test_data.sql`
- MySQL: `../connectors/mysql/testdata/test_data.sql`
- MSSQL: `../connectors/mssql/testdata/test_data.sql`
- ClickHouse: `../connectors/clickhouse/testdata/test_data.sql` 