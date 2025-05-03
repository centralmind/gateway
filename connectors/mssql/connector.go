package mssql

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/centralmind/gateway/castx"
	"github.com/centralmind/gateway/connectors"
	"github.com/centralmind/gateway/model"
	"github.com/jmoiron/sqlx"
	_ "github.com/microsoft/go-mssqldb"
	"golang.org/x/xerrors"
)

func init() {
	connectors.Register[Config](func(cfg Config) (connectors.Connector, error) {

		connStr := cfg.ConnectionString()

		db, err := sqlx.Connect("sqlserver", connStr)
		if err != nil {
			return nil, fmt.Errorf("unable to connect to mssql: %v", err)
		}
		return &Connector{
			config: cfg,
			db:     db,
			base:   &connectors.BaseConnector{DB: db},
		}, nil
	})
}

// Connector implements the connectors.Connector interface for Microsoft SQL Server
type Connector struct {
	config Config
	db     *sqlx.DB
	base   *connectors.BaseConnector
}

func (c Connector) Config() connectors.Config {
	return c.config
}

// GuessColumnType implements TypeGuesser interface for MSSQL
func (c *Connector) GuessColumnType(sqlType string) model.ColumnType {
	upperType := strings.ToUpper(sqlType)

	// String types
	switch upperType {
	case "VARCHAR", "CHAR", "TEXT", "NVARCHAR", "NCHAR", "NTEXT",
		"XML", "UNIQUEIDENTIFIER":
		return model.TypeString
	}

	// Numeric types
	switch upperType {
	case "DECIMAL", "NUMERIC", "FLOAT", "REAL", "MONEY", "SMALLMONEY":
		return model.TypeNumber
	}

	// Integer types
	switch upperType {
	case "INT", "BIGINT", "SMALLINT", "TINYINT":
		return model.TypeInteger
	}

	// Boolean type
	switch upperType {
	case "BIT":
		return model.TypeBoolean
	}

	// Date/Time types
	switch upperType {
	case "DATE", "TIME", "DATETIME", "DATETIME2", "DATETIMEOFFSET", "SMALLDATETIME":
		return model.TypeDatetime
	}

	// Binary types
	switch upperType {
	case "BINARY", "VARBINARY", "IMAGE":
		return model.TypeString
	}

	// Default to string for unknown types
	return model.TypeString
}

func (c Connector) Sample(ctx context.Context, table model.Table) ([]map[string]any, error) {
	// Use the schema from config, default to 'dbo' if not specified
	schema := "dbo"
	if c.config.Schema != "" {
		schema = c.config.Schema
	}

	// Create schema-qualified table name
	qualifiedTableName := fmt.Sprintf("[%s].[%s]", schema, table.Name)

	rows, err := c.db.NamedQuery(fmt.Sprintf("SELECT TOP 5 * FROM %s", qualifiedTableName), map[string]any{})
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
	// Use the schema from config, default to 'dbo' if not specified
	schema := "dbo"
	if c.config.Schema != "" {
		schema = c.config.Schema
	}

	// Create a map for quick lookups if tablesList is provided
	tableSet := make(map[string]bool)
	if len(tablesList) > 0 {
		for _, table := range tablesList {
			tableSet[table] = true
		}
	}

	// Build query with or without table filter
	var query string
	var args []interface{}
	args = append(args, schema) // First parameter is always schema

	if len(tablesList) > 0 {
		// Build dynamic IN clause with proper parameterization
		placeholders := make([]string, len(tablesList))
		for i, table := range tablesList {
			placeholders[i] = fmt.Sprintf("@p%d", i+2) // Start from @p2 since @p1 is schema
			args = append(args, table)
		}

		query = fmt.Sprintf(`
			SELECT TABLE_NAME 
			FROM INFORMATION_SCHEMA.TABLES 
			WHERE TABLE_SCHEMA = @p1 
			AND TABLE_TYPE = 'BASE TABLE'
			AND TABLE_NAME IN (%s)`, strings.Join(placeholders, ","))
	} else {
		query = `
			SELECT TABLE_NAME 
			FROM INFORMATION_SCHEMA.TABLES 
			WHERE TABLE_SCHEMA = @p1 
			AND TABLE_TYPE = 'BASE TABLE'`
	}

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
		qualifiedTableName := fmt.Sprintf("[%s].[%s]", schema, tableName)
		countQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s", qualifiedTableName)
		err = c.db.Get(&rowCount, countQuery)
		if err != nil {
			return nil, xerrors.Errorf("unable to get row count for table %s: %w", tableName, err)
		}

		table := model.Table{
			Name:     qualifiedTableName,
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
				// Keep as string for date-time as SQL Server can handle ISO8601 strings
				continue
			case "string":
				// No conversion needed for strings
				continue
			}
		}
	}

	rows, err := c.db.NamedQuery(endpoint.Query, processed)
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
	schema := "dbo"
	if c.config.Schema != "" {
		schema = c.config.Schema
	}

	rows, err := c.db.QueryContext(
		ctx,
		`SELECT 
			c.COLUMN_NAME,
			c.DATA_TYPE,
			c.IS_NULLABLE,
			CASE WHEN pk.COLUMN_NAME IS NOT NULL THEN 1 ELSE 0 END as IS_PRIMARY_KEY
		FROM INFORMATION_SCHEMA.COLUMNS c
		LEFT JOIN (
			SELECT ku.COLUMN_NAME
			FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS tc
			JOIN INFORMATION_SCHEMA.KEY_COLUMN_USAGE ku
				ON tc.CONSTRAINT_NAME = ku.CONSTRAINT_NAME
			WHERE tc.CONSTRAINT_TYPE = 'PRIMARY KEY'
				AND ku.TABLE_NAME = @p1
				AND ku.TABLE_SCHEMA = @p2
		) pk ON c.COLUMN_NAME = pk.COLUMN_NAME
		WHERE c.TABLE_NAME = @p1
		AND c.TABLE_SCHEMA = @p2`,
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
