package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/centralmind/gateway/castx"
	"github.com/centralmind/gateway/connectors"
	"github.com/centralmind/gateway/model"
	_ "github.com/glebarez/go-sqlite"
	"github.com/jmoiron/sqlx"
	"golang.org/x/xerrors"
)

func init() {
	connectors.Register[Config](func(cfg Config) (connectors.Connector, error) {
		connStr := cfg.ConnectionString()
		// Remove sqlite:// prefix if present
		connStr = strings.TrimPrefix(connStr, "sqlite://")

		// Add read-only mode if specified
		if cfg.ReadOnly {
			if strings.Contains(connStr, "?") {
				connStr += "&mode=ro"
			} else {
				connStr += "?mode=ro"
			}
		}

		db, err := sqlx.Connect("sqlite", connStr)
		if err != nil {
			return nil, fmt.Errorf("unable to connect to sqlite: %v", err)
		}
		return &Connector{
			config: cfg,
			db:     db,
			base:   &connectors.BaseConnector{DB: db},
		}, nil
	})
}

// Connector implements the connectors.Connector interface for SQLite
type Connector struct {
	config Config
	db     *sqlx.DB
	base   *connectors.BaseConnector
}

func (c Connector) Config() connectors.Config {
	return c.config
}

// GuessColumnType implements TypeGuesser interface for SQLite
func (c *Connector) GuessColumnType(sqlType string) model.ColumnType {
	upperType := strings.ToUpper(sqlType)

	// String types
	switch upperType {
	case "TEXT", "VARCHAR", "CHAR", "CLOB":
		return model.TypeString
	}

	// Numeric types
	switch upperType {
	case "REAL", "FLOAT", "DOUBLE":
		return model.TypeNumber
	}

	// Integer types
	switch upperType {
	case "INTEGER", "INT", "BIGINT", "SMALLINT", "TINYINT":
		return model.TypeInteger
	}

	// Boolean type
	switch upperType {
	case "BOOLEAN":
		return model.TypeBoolean
	}

	// Date/Time types
	switch upperType {
	case "DATETIME", "DATE", "TIME":
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

func (c Connector) Discovery(ctx context.Context, tablesList []string) ([]model.Table, error) {
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
		// If specific tables are requested, build a query with IN clause
		placeholders := make([]string, len(tablesList))
		args = make([]interface{}, len(tablesList))
		for i, table := range tablesList {
			placeholders[i] = "?"
			args[i] = table
		}
		query = fmt.Sprintf(`
			SELECT name 
			FROM sqlite_master 
			WHERE type='table' 
			AND name NOT LIKE 'sqlite_%%'
			AND name IN (%s)`, strings.Join(placeholders, ","))
	} else {
		// Otherwise, query all tables
		query = `
			SELECT name 
			FROM sqlite_master 
			WHERE type='table' 
			AND name NOT LIKE 'sqlite_%'`
	}

	// Query tables in the database
	rows, err := c.db.QueryContext(ctx, query, args...)
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
	// Query column information from SQLite
	rows, err := c.db.Query(`
		SELECT name, type, pk
		FROM pragma_table_info(?)
		ORDER BY cid`, tableName)
	if err != nil {
		return nil, xerrors.Errorf("unable to query columns: %w", err)
	}
	defer rows.Close()

	var columns []model.ColumnSchema
	for rows.Next() {
		var name, sqlType string
		var pk int
		if err := rows.Scan(&name, &sqlType, &pk); err != nil {
			return nil, xerrors.Errorf("unable to scan column info: %w", err)
		}

		// Extract base type without length/precision
		baseType := strings.Split(sqlType, "(")[0]
		baseType = strings.TrimSpace(baseType)

		column := model.ColumnSchema{
			Name:       name,
			Type:       c.GuessColumnType(baseType),
			PrimaryKey: pk == 1,
		}
		columns = append(columns, column)
	}
	return columns, nil
}

func (c *Connector) InferQuery(ctx context.Context, query string) ([]model.ColumnSchema, error) {
	// Create a temporary view to analyze the query
	viewName := "temp_view_" + fmt.Sprintf("%d", ctx.Value("request_id"))
	createViewSQL := fmt.Sprintf("CREATE TEMPORARY VIEW %s AS %s", viewName, query)
	_, err := c.db.Exec(createViewSQL)
	if err != nil {
		return nil, xerrors.Errorf("unable to create temporary view: %w", err)
	}
	defer c.db.Exec("DROP VIEW " + viewName)

	// Get column information from the temporary view
	columns, err := c.LoadsColumns(ctx, viewName)
	if err != nil {
		return nil, xerrors.Errorf("unable to load columns from temporary view: %w", err)
	}

	return columns, nil
}
