package duckdb

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"

	"github.com/centralmind/gateway/castx"
	"github.com/centralmind/gateway/connectors"
	"github.com/centralmind/gateway/model"
	"github.com/jmoiron/sqlx"
	_ "github.com/marcboeker/go-duckdb"
	"golang.org/x/xerrors"
)

func init() {
	connectors.Register[Config](func(cfg Config) (connectors.Connector, error) {
		connStr := cfg.ConnectionString()

		db, err := sqlx.Connect("duckdb", connStr+"&access_mode=READ_ONLY")
		if err != nil {
			return nil, fmt.Errorf("unable to connect to duckdb: %v", err)
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
	tx, err := c.db.BeginTxx(ctx, &sql.TxOptions{
		ReadOnly: true,
	})
	if err != nil {
		return nil, xerrors.Errorf("BeginTx failed with error: %w", err)
	}
	defer tx.Commit()

	rows, err := tx.NamedQuery(fmt.Sprintf("SELECT * FROM %s LIMIT 5", table.Name), map[string]any{})
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
	rows, err := c.db.Query(`
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
		err = c.db.Get(&rowCount, countQuery)
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

	// Convert parameters to their proper types based on endpoint parameter definitions
	for _, param := range endpoint.Params {
		if value, ok := processed[param.Name]; ok {
			switch param.Type {
			case "integer":
				if strVal, ok := value.(string); ok {
					if intVal, err := strconv.Atoi(strVal); err == nil {
						processed[param.Name] = intVal
					}
				}
			case "number":
				if strVal, ok := value.(string); ok {
					if floatVal, err := strconv.ParseFloat(strVal, 64); err == nil {
						processed[param.Name] = floatVal
					}
				}
			case "boolean":
				if strVal, ok := value.(string); ok {
					if boolVal, err := strconv.ParseBool(strVal); err == nil {
						processed[param.Name] = boolVal
					}
				}
			case "date-time":
				// Keep as string for date-time as DuckDB can handle ISO8601 strings
				continue
			case "string":
				// No conversion needed for strings
				continue
			}
		}
	}

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
	tx, err := c.db.BeginTxx(ctx, &sql.TxOptions{
		ReadOnly: true,
	})
	if err != nil {
		return nil, xerrors.Errorf("BeginTx failed with error: %w", err)
	}
	defer tx.Commit()

	rows, err := tx.QueryContext(
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
	return c.base.InferResultColumns(ctx, query, c)
}
