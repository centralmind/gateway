package duckdb

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/centralmind/gateway/castx"
	"github.com/centralmind/gateway/connectors"
	"github.com/centralmind/gateway/model"
	"github.com/jmoiron/sqlx"
	_ "github.com/marcboeker/go-duckdb/v2"
	"golang.org/x/xerrors"
)

func init() {
	connectors.Register[Config](func(cfg Config) (connectors.Connector, error) {
		connStr := cfg.ConnectionString()
		// Remove duckdb:// prefix if present
		connStr = strings.TrimPrefix(connStr, "duckdb://")

		safetyGuardRails := "access_mode=READ_ONLY&allow_community_extensions=false"

		// Add READ_ONLY mode if connection string is not empty and not in-memory
		if connStr != "" && !strings.Contains(connStr, ":memory:") {
			if strings.Contains(connStr, "?") {
				connStr += "&" + safetyGuardRails
			} else {
				connStr += "?" + safetyGuardRails
			}
		}

		db, err := sqlx.Connect("duckdb", connStr)
		if err != nil {
			return nil, fmt.Errorf("unable to connect to duckdb: %v", err)
		}

		// Execute initialization SQL if provided
		if cfg.InitSQL != "" {
			// Split SQL commands by semicolon and execute each one

			commands := strings.Split(cfg.InitSQL, ";")
			for _, cmd := range commands {
				cmd = strings.TrimSpace(cmd)
				if cmd == "" {
					continue
				}
				_, err = db.Exec(cmd)
				if err != nil {
					return nil, fmt.Errorf("failed to execute initialization SQL: %v", err)
				}
			}
		}

		return &Connector{
			config: cfg,
			db:     db,
			base:   &connectors.BaseConnector{DB: db},
		}, nil
	})
}

// Connector implements the connectors.Connector interface for DuckDB
type Connector struct {
	config Config
	db     *sqlx.DB
	base   *connectors.BaseConnector
}

func (c Connector) Config() connectors.Config {
	return c.config
}

// GuessColumnType implements TypeGuesser interface for DuckDB
func (c *Connector) GuessColumnType(sqlType string) model.ColumnType {
	upperType := strings.ToUpper(sqlType)

	// String types
	switch upperType {
	case "VARCHAR", "CHAR", "TEXT", "STRING", "ENUM", "UUID":
		return model.TypeString
	}

	// Numeric types
	switch upperType {
	case "DECIMAL", "NUMERIC", "FLOAT", "DOUBLE", "REAL":
		return model.TypeNumber
	}

	// Integer types
	switch upperType {
	case "INTEGER", "BIGINT", "SMALLINT", "TINYINT", "UBIGINT", "UINTEGER", "USMALLINT", "UTINYINT":
		return model.TypeInteger
	}

	// Boolean type
	switch upperType {
	case "BOOLEAN":
		return model.TypeBoolean
	}

	// Date/Time types
	switch upperType {
	case "DATE", "TIME", "TIMESTAMP", "TIMESTAMP WITH TIME ZONE", "TIMESTAMP WITHOUT TIME ZONE":
		return model.TypeDatetime
	}

	// Default to string for unknown types
	return model.TypeString
}

func (c Connector) Sample(ctx context.Context, table model.Table) ([]map[string]any, error) {
	rows, err := c.db.NamedQueryContext(ctx, fmt.Sprintf("SELECT * FROM %s LIMIT 5", table.Name), map[string]any{})
	if err != nil {
		return nil, xerrors.Errorf("unable to query db: %w", err)
	}
	defer rows.Close()

	res := make([]map[string]any, 0, 5)
	for rows.Next() {
		row := map[string]any{}
		if err := rows.MapScan(row); err != nil {
			return nil, xerrors.Errorf("unable to scan row: %w", err)
		}
		res = append(res, row)
	}
	return res, nil
}

func (c Connector) Discovery(ctx context.Context) ([]model.Table, error) {
	// Query all tables in the database
	rows, err := c.db.QueryContext(ctx, `
		SELECT table_name 
		FROM information_schema.tables 
		WHERE table_type = 'BASE TABLE'
		AND table_schema = 'main'`)
	if err != nil {
		return nil, xerrors.Errorf("unable to query tables: %w", err)
	}
	defer rows.Close()

	var tables []model.Table
	for rows.Next() {
		var tableName string
		if err := rows.Scan(&tableName); err != nil {
			return nil, xerrors.Errorf("unable to scan table name: %w", err)
		}

		columns, err := c.LoadsColumns(ctx, tableName)
		if err != nil {
			return nil, xerrors.Errorf("unable to load columns for table %s: %w", tableName, err)
		}

		// Get the total row count for this table
		var rowCount int
		countQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s", tableName)
		err = c.db.GetContext(ctx, &rowCount, countQuery)
		if err != nil {
			return nil, xerrors.Errorf("unable to get row count for table %s: %w", tableName, err)
		}

		table := model.Table{
			Name:     tableName,
			Columns:  columns,
			RowCount: rowCount,
		}
		tables = append(tables, table)
	}
	return tables, nil
}

func (c Connector) Ping(ctx context.Context) error {
	rows, err := c.db.QueryContext(ctx, "SELECT 1")
	if err != nil {
		return xerrors.Errorf("unable to ping db: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var res int
		if err := rows.Scan(&res); err != nil {
			return xerrors.Errorf("unable to scan ping result: %w", err)
		}
	}
	if rows.Err() != nil {
		return xerrors.Errorf("rows fetcher failed: %w", err)
	}
	return nil
}

func (c Connector) Query(ctx context.Context, endpoint model.Endpoint, params map[string]any) ([]map[string]any, error) {
	processed, err := castx.ParamsE(endpoint, params)
	if err != nil {
		return nil, xerrors.Errorf("unable to process params: %w", err)
	}

	// If there are no parameters to process, use direct query execution
	if len(processed) == 0 {
		rows, err := c.db.QueryContext(ctx, endpoint.Query)
		if err != nil {
			return nil, xerrors.Errorf("unable to execute query: %w", err)
		}
		defer rows.Close()

		// Get column names
		columns, err := rows.Columns()
		if err != nil {
			return nil, xerrors.Errorf("unable to get columns: %w", err)
		}

		// Create a slice of interface{} to store the values
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		for i := range values {
			valuePtrs[i] = &values[i]
		}

		var result []map[string]any
		for rows.Next() {
			if err := rows.Scan(valuePtrs...); err != nil {
				return nil, xerrors.Errorf("unable to scan row: %w", err)
			}

			row := make(map[string]any)
			for i, col := range columns {
				row[col] = values[i]
			}
			result = append(result, row)
		}
		return result, nil
	}

	// For parameterized queries, use transaction-based approach
	tx, err := c.db.BeginTxx(ctx, &sql.TxOptions{
		ReadOnly: c.Config().Readonly(),
	})
	if err != nil {
		return nil, xerrors.Errorf("BeginTx failed with error: %w", err)
	}
	defer tx.Commit()

	rows, err := tx.NamedQuery(endpoint.Query, processed)
	if err != nil {
		return nil, xerrors.Errorf("unable to execute query: %w", err)
	}
	defer rows.Close()

	res := make([]map[string]any, 0)
	for rows.Next() {
		row := map[string]any{}
		if err := rows.MapScan(row); err != nil {
			return nil, xerrors.Errorf("unable to scan row: %w", err)
		}
		res = append(res, row)
	}
	return res, nil
}

func (c Connector) LoadsColumns(ctx context.Context, tableName string) ([]model.ColumnSchema, error) {
	rows, err := c.db.QueryContext(
		ctx,
		`SELECT 
			column_name,
			data_type,
			is_nullable,
			(SELECT true 
			 FROM information_schema.table_constraints tc 
			 JOIN information_schema.key_column_usage kcu 
				ON tc.constraint_name = kcu.constraint_name 
			 WHERE tc.constraint_type = 'PRIMARY KEY' 
				AND kcu.table_name = c.table_name 
				AND kcu.column_name = c.column_name
			) as is_primary_key
		FROM information_schema.columns c
		WHERE table_name = $1
		AND table_schema = 'main'`,
		tableName,
	)
	if err != nil {
		return nil, xerrors.Errorf("unable to query columns: %w", err)
	}
	defer rows.Close()

	var columns []model.ColumnSchema
	for rows.Next() {
		var name, dataType, isNullable string
		var isPrimaryKey *bool
		if err := rows.Scan(&name, &dataType, &isNullable, &isPrimaryKey); err != nil {
			return nil, xerrors.Errorf("unable to scan column info: %w", err)
		}
		columns = append(columns, model.ColumnSchema{
			Name:       name,
			Type:       c.GuessColumnType(dataType),
			PrimaryKey: isPrimaryKey != nil && *isPrimaryKey,
		})
	}
	return columns, nil
}

// InferQuery implements the Connector interface
func (c *Connector) InferQuery(ctx context.Context, query string) ([]model.ColumnSchema, error) {
	// Check if query contains any SQL parameters
	// Look for :name, $1, or ? not inside quotes
	hasParams := false
	inQuote := false
	quoteChar := rune(0)

	for i, ch := range query {
		// Handle quotes
		if ch == '\'' || ch == '"' {
			if !inQuote {
				inQuote = true
				quoteChar = ch
			} else if ch == quoteChar {
				// Check if it's an escaped quote
				if i > 0 && query[i-1] != '\\' {
					inQuote = false
					quoteChar = rune(0)
				}
			}
			continue
		}

		// Only check for parameters when not inside quotes
		if !inQuote {
			// Check for named parameters (:name)
			if ch == ':' && i+1 < len(query) && (query[i+1] >= 'a' && query[i+1] <= 'z' || query[i+1] >= 'A' && query[i+1] <= 'Z') {
				hasParams = true
				break
			}
			// Check for positional parameters ($1)
			if ch == '$' && i+1 < len(query) && query[i+1] >= '0' && query[i+1] <= '9' {
				hasParams = true
				break
			}
			// Check for question mark parameters
			if ch == '?' {
				hasParams = true
				break
			}
		}
	}

	if hasParams {
		return c.base.InferResultColumns(ctx, query, c)
	}

	// For queries without parameters, execute directly
	rows, err := c.db.QueryContext(ctx, query)
	if err != nil {
		return nil, xerrors.Errorf("unable to execute query for inference: %w", err)
	}
	defer rows.Close()

	// Get column types directly from the result
	columnTypes, err := rows.ColumnTypes()
	if err != nil {
		return nil, xerrors.Errorf("unable to get column types: %w", err)
	}

	var columns []model.ColumnSchema
	for _, col := range columnTypes {
		columns = append(columns, model.ColumnSchema{
			Name: col.Name(),
			Type: c.GuessColumnType(col.DatabaseTypeName()),
		})
	}

	return columns, nil
}
