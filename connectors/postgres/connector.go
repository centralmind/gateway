package postgres

import (
	"context"
	"fmt"
	"strings"

	"github.com/centralmind/gateway/connectors"

	"database/sql"

	"github.com/centralmind/gateway/castx"
	"github.com/centralmind/gateway/model"
	"github.com/jackc/pgx/v4/stdlib"
	"github.com/jmoiron/sqlx"
	"golang.org/x/xerrors"
)

func init() {
	connectors.Register[Config](func(cfg Config) (connectors.Connector, error) {
		c, err := cfg.MakeConfig()
		if err != nil {
			return nil, xerrors.Errorf("unable to prepare pg config: %w", err)
		}
		db := sqlx.NewDb(stdlib.OpenDB(*c), "pgx")
		return &Connector{
			config: cfg,
			db:     db,
			base:   &connectors.BaseConnector{DB: db},
		}, nil
	})
	connectors.RegisterAlias("postgres", "postgresql")
}

// Connector implements the connectors.Connector interface for PostgreSQL
type Connector struct {
	config Config
	db     *sqlx.DB
	base   *connectors.BaseConnector
}

func (c Connector) Config() connectors.Config {
	return c.config
}

// GuessColumnType implements TypeGuesser interface for PostgreSQL
func (c *Connector) GuessColumnType(sqlType string) model.ColumnType {
	upperType := strings.ToUpper(sqlType)

	// Array types (check first as they contain other type names)
	if strings.Contains(upperType, "[]") || strings.Contains(upperType, "ARRAY") {
		return model.TypeArray
	}

	// Object types
	switch upperType {
	case "JSON", "JSONB":
		return model.TypeObject
	}

	// String types
	switch upperType {
	case "VARCHAR", "CHAR", "TEXT", "NAME", "BPCHAR", "BYTEA", "UUID", "XML", "CITEXT",
		"CHARACTER", "CHARACTER VARYING", "NCHAR", "NVARCHAR":
		return model.TypeString
	}

	// Numeric types
	switch upperType {
	case "DECIMAL", "NUMERIC", "REAL", "DOUBLE PRECISION", "MONEY":
		return model.TypeNumber
	}

	// Integer types
	switch upperType {
	case "INT4", "INT8", "SMALLINT", "INTEGER", "BIGINT", "SMALLSERIAL", "SERIAL", "BIGSERIAL":
		return model.TypeInteger
	}

	// Boolean type
	switch upperType {
	case "BOOLEAN", "BOOL":
		return model.TypeBoolean
	}

	// Date/Time types
	switch upperType {
	case "DATE", "TIME", "TIMETZ", "TIMESTAMP", "TIMESTAMPTZ", "INTERVAL":
		return model.TypeDatetime
	}

	// Default to string for unknown types
	return model.TypeString
}

// InferResultColumns returns column information for the given query
func (c *Connector) InferResultColumns(ctx context.Context, query string) ([]model.ColumnSchema, error) {
	return c.base.InferResultColumns(ctx, query, c)
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

func (c Connector) Discovery(ctx context.Context, tablesList []string) ([]model.Table, error) {
	tx, err := c.base.DB.BeginTxx(ctx, &sql.TxOptions{
		ReadOnly: c.Config().Readonly(),
	})
	if err != nil {
		return nil, xerrors.Errorf("BeginTx failed with error: %w", err)
	}
	defer tx.Commit()

	// Create a map for quick lookups if tablesList is provided
	tableSet := make(map[string]bool)
	if len(tablesList) > 0 {
		for _, table := range tablesList {
			tableSet[table] = true
		}
	}

	var query string
	var args []interface{}

	if len(tablesList) > 0 {
		// If specific tables are requested, only query those
		placeholders := make([]string, len(tablesList))
		args = make([]interface{}, len(tablesList))
		for i, table := range tablesList {
			placeholders[i] = fmt.Sprintf("$%d", i+1)
			args[i] = table
		}
		query = fmt.Sprintf(`
			SELECT table_name, table_schema
			FROM information_schema.tables 
			WHERE table_type = 'BASE TABLE'
			AND table_name IN (%s)
		`, strings.Join(placeholders, ","))
	} else {
		// Otherwise, query all tables
		query = `
			SELECT table_name, table_schema
			FROM information_schema.tables 
			WHERE table_type = 'BASE TABLE'
		`
	}

	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tables []model.Table
	for rows.Next() {
		var tableName, tableSchema string
		if err := rows.Scan(&tableName, &tableSchema); err != nil {
			return nil, err
		}
		if c.config.Schema != "" {
			if tableSchema != c.config.Schema {
				continue
			}
		}

		columns, err := c.LoadsColumns(ctx, tableName)
		if err != nil {
			return nil, err
		}

		fqtn := fmt.Sprintf(`"%s"."%s"`, tableSchema, tableName)
		// Get the total row count for this table
		var rowCount int
		countQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s", fqtn)
		err = c.db.Get(&rowCount, countQuery)
		if err != nil {
			return nil, xerrors.Errorf("unable to get row count for table %s: %w", tableName, err)
		}

		table := model.Table{
			Name:     fqtn,
			Columns:  columns,
			RowCount: rowCount,
		}
		tables = append(tables, table)
	}
	return tables, nil
}

func (c Connector) Ping(ctx context.Context) error {
	rows, err := c.db.QueryContext(ctx, "select 1+1")
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

	tx, err := c.db.BeginTxx(ctx, &sql.TxOptions{
		ReadOnly: c.Config().Readonly(),
	})
	if err != nil {
		return nil, xerrors.Errorf("BeginTx failed with error: %w", err)
	}
	defer tx.Commit()

	rows, err := tx.NamedQuery(endpoint.Query, processed)
	if err != nil {
		return nil, xerrors.Errorf("unable to query db: %w", err)
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
	// Use the schema from config, default to 'public' if not specified
	schema := "public"
	if c.config.Schema != "" {
		schema = c.config.Schema
	}
	rows, err := tx.QueryContext(
		ctx,
		`SELECT 
			c.column_name, 
			c.data_type, 
			c.is_nullable,
			(SELECT true 
			 FROM information_schema.table_constraints tc 
			 JOIN information_schema.key_column_usage kcu 
				ON tc.constraint_name = kcu.constraint_name 
				AND tc.table_schema = kcu.table_schema 
				AND tc.table_name = kcu.table_name 
			 WHERE tc.constraint_type = 'PRIMARY KEY' 
				AND tc.table_name = $1 
				AND tc.table_schema = $2 
				AND kcu.column_name = c.column_name) is not null as is_primary_key
		FROM information_schema.columns c 
		WHERE c.table_name = $1 
		AND c.table_schema = $2`,
		tableName, schema,
	)
	if err != nil {
		return nil, xerrors.Errorf("unable to query columns: %w", err)
	}
	defer rows.Close()

	var columns []model.ColumnSchema
	for rows.Next() {
		var name, dataType, isNullable string
		var isPrimaryKey bool
		if err := rows.Scan(&name, &dataType, &isNullable, &isPrimaryKey); err != nil {
			return nil, xerrors.Errorf("unable to scan column info: %w", err)
		}
		columns = append(columns, model.ColumnSchema{
			Name:       name,
			Type:       c.GuessColumnType(dataType),
			PrimaryKey: isPrimaryKey,
		})
	}
	return columns, nil
}

// InferQuery implements the Connector interface
func (c *Connector) InferQuery(ctx context.Context, query string) ([]model.ColumnSchema, error) {
	return c.base.InferResultColumns(ctx, query, c)
}
