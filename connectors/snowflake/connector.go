package snowflake

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"strings"

	"github.com/centralmind/gateway/connectors"

	"github.com/centralmind/gateway/castx"
	"github.com/centralmind/gateway/model"
	"github.com/jmoiron/sqlx"
	_ "github.com/snowflakedb/gosnowflake"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"
)

//go:embed readme.md
var docString string

func init() {
	connectors.Register(func(cfg Config) (connectors.Connector, error) {
		dsn, err := cfg.MakeDSN()
		if err != nil {
			return nil, xerrors.Errorf("unable to prepare Snowflake config: %w", err)
		}
		db, err := sqlx.Open("snowflake", dsn)
		if err != nil {
			// Extract the underlying error for better diagnosis
			if strings.Contains(err.Error(), "account is empty") {
				return nil, xerrors.Errorf(
					"Snowflake account identifier is missing. "+
						"Please specify either:\n"+
						"  1. A complete connection string with account identifier (e.g., 'user:password@account/database/schema?warehouse=WAREHOUSE&role=ROLE'), or\n"+
						"  2. Individual connection parameters including the 'account' field\n"+
						"Original error: %w", err)
			}
			return nil, xerrors.Errorf("unable to open Snowflake database connection: %w", err)
		}
		return &Connector{
			config: cfg,
			db:     db,
			base:   &connectors.BaseConnector{DB: db},
		}, nil
	})
}

type Config struct {
	Account    string
	Database   string
	User       string
	Password   string
	Warehouse  string
	Schema     string
	Role       string
	ConnString string `yaml:"conn_string"`
	IsReadonly bool   `yaml:"is_readonly"`
}

func (c Config) Readonly() bool {
	return c.IsReadonly
}

// UnmarshalYAML implements the yaml.Unmarshaler interface to allow for both
// direct connection string or full configuration objects in YAML
func (c *Config) UnmarshalYAML(value *yaml.Node) error {
	// Try to unmarshal as a string (connection string)
	var connString string
	if err := value.Decode(&connString); err == nil && len(connString) > 0 {
		c.ConnString = connString
		return nil
	}

	// If that didn't work, try to unmarshal as a full config object
	type configAlias Config // Use alias to avoid infinite recursion
	var alias configAlias
	if err := value.Decode(&alias); err != nil {
		return err
	}

	*c = Config(alias)
	return nil
}

func (c Config) ExtraPrompt() []string {
	return []string{}
}

func (c Config) MakeDSN() (string, error) {
	// If connection string is provided, use it directly
	if c.ConnString != "" {
		return c.ConnString, nil
	}

	// Otherwise, build the DSN from individual fields
	dsn := fmt.Sprintf("%s:%s@%s/%s/%s?warehouse=%s&role=%s", c.User, c.Password, c.Account, c.Database, c.Schema, c.Warehouse, c.Role)

	return dsn, nil
}

func (c Config) Type() string {
	return "snowflake"
}

func (c Config) Doc() string {
	return docString
}

type Connector struct {
	config Config
	db     *sqlx.DB
	base   *connectors.BaseConnector
}

func (c Connector) Config() connectors.Config {
	return c.config
}

func (c Connector) Sample(ctx context.Context, table model.Table) ([]map[string]any, error) {
	rows, err := c.db.NamedQuery(fmt.Sprintf("SELECT * FROM %s LIMIT 5", table.Name), map[string]any{})
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
	// Create base query
	queryBase := fmt.Sprintf("SHOW TABLES IN SCHEMA %s.%s", c.config.Database, c.config.Schema)

	var allTables []model.Table

	if len(tablesList) > 0 {
		// For specific tables, we need to get all tables and filter manually
		// because Snowflake SHOW TABLES doesn't support WHERE IN or multiple LIKE conditions
		tables, err := c.executeTableQuery(ctx, queryBase)
		if err != nil {
			return nil, err
		}

		// Create a map for quick lookups
		tableSet := make(map[string]bool)
		for _, table := range tablesList {
			tableSet[strings.ToUpper(table)] = true
		}

		// Filter tables
		for _, table := range tables {
			if tableSet[strings.ToUpper(table.Name)] {
				allTables = append(allTables, table)
			}
		}
	} else {
		// If no specific tables are requested, get all tables
		tables, err := c.executeTableQuery(ctx, queryBase)
		if err != nil {
			return nil, err
		}
		allTables = tables
	}

	return allTables, nil
}

// Helper function to execute table queries and process results
func (c Connector) executeTableQuery(ctx context.Context, query string) ([]model.Table, error) {
	rows, err := c.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tables []model.Table
	for rows.Next() {
		// SHOW TABLES returns a different number of columns depending on Snowflake version
		// We'll scan all values dynamically
		columns, err := rows.Columns()
		if err != nil {
			return nil, xerrors.Errorf("failed to get columns: %w", err)
		}

		// Create a slice to hold the values
		// Use sql.RawBytes to prevent automatic type conversion
		values := make([]sql.RawBytes, len(columns))
		scanArgs := make([]interface{}, len(columns))
		for i := range values {
			scanArgs[i] = &values[i]
		}

		// Scan the row
		if err := rows.Scan(scanArgs...); err != nil {
			return nil, xerrors.Errorf("failed to scan table row: %w", err)
		}

		// Create a map of column name to value for easier access
		rowMap := make(map[string]interface{})
		for i, colName := range columns {
			// Convert RawBytes to string
			if values[i] != nil {
				rowMap[colName] = string(values[i])
			} else {
				rowMap[colName] = nil
			}
		}

		// Extract the required fields
		tableName, ok := rowMap["name"].(string)
		if !ok {
			continue
		}

		// Check if table is dropped (if column exists)
		if droppedOn, exists := rowMap["dropped_on"]; exists && droppedOn != nil && droppedOn != "" {
			continue
		}

		// Check if table is external
		if isExternal, exists := rowMap["is_external"]; exists {
			if extStr, ok := isExternal.(string); ok && extStr == "Y" {
				continue
			}
		}

		tableColumns, err := c.LoadsColumns(ctx, tableName)
		if err != nil {
			return nil, err
		}

		// Get row count
		var tableRowCount int
		if rowCountVal, exists := rowMap["rows"]; exists && rowCountVal != nil {
			if rowStr, ok := rowCountVal.(string); ok && rowStr != "" {
				// Parse the string to int
				fmt.Sscanf(rowStr, "%d", &tableRowCount)
			}
		}

		// If row count is still 0, fallback to COUNT query
		if tableRowCount == 0 {
			countQuery := fmt.Sprintf("SELECT COUNT(*) FROM \"%s\".\"%s\".\"%s\"", c.config.Database, c.config.Schema, tableName)
			err = c.db.Get(&tableRowCount, countQuery)
			if err != nil {
				return nil, xerrors.Errorf("unable to get row count for table %s: %w", tableName, err)
			}
		}

		table := model.Table{
			Name:     tableName,
			Columns:  tableColumns,
			RowCount: tableRowCount,
		}
		tables = append(tables, table)
	}
	return tables, nil
}

func (c Connector) Ping(ctx context.Context) error {
	return c.db.PingContext(ctx)
}

func (c Connector) Query(ctx context.Context, endpoint model.Endpoint, params map[string]any) ([]map[string]any, error) {
	processed, err := castx.ParamsE(endpoint, params)
	if err != nil {
		return nil, xerrors.Errorf("unable to process params: %w", err)
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
	// First, get all columns information
	rows, err := c.db.QueryContext(
		ctx,
		`SELECT 
			COLUMN_NAME,
			DATA_TYPE,
			NUMERIC_PRECISION,
			NUMERIC_SCALE
		FROM information_schema.columns
		WHERE table_name = ?
		AND table_schema = ?
		AND table_catalog = ?
		ORDER BY ORDINAL_POSITION`,
		tableName, c.config.Schema, c.config.Database,
	)
	if err != nil {
		return nil, xerrors.Errorf("unable to query columns: %w", err)
	}
	defer rows.Close()

	var columns []model.ColumnSchema
	columnMap := make(map[string]*model.ColumnSchema)

	for rows.Next() {
		var name, dataType string
		var numericPrecision, numericScale sql.NullInt64
		if err := rows.Scan(&name, &dataType, &numericPrecision, &numericScale); err != nil {
			return nil, err
		}

		// Determine the column type
		columnType := c.GuessColumnType(dataType)

		// For NUMBER type, check if it's an integer based on scale
		if strings.ToUpper(dataType) == "NUMBER" && numericScale.Valid && numericScale.Int64 == 0 {
			columnType = model.TypeInteger
		}

		col := model.ColumnSchema{
			Name:       name,
			Type:       columnType,
			PrimaryKey: false,
		}
		columns = append(columns, col)
		columnMap[name] = &columns[len(columns)-1]
	}

	// Now try to get primary key information using SHOW PRIMARY KEYS
	// This command is more reliable than querying KEY_COLUMN_USAGE
	pkQuery := fmt.Sprintf("SHOW PRIMARY KEYS IN TABLE \"%s\".\"%s\".\"%s\"", c.config.Database, c.config.Schema, tableName)
	pkRows, err := c.db.QueryContext(ctx, pkQuery)
	if err == nil {
		defer pkRows.Close()

		// Process primary key information
		for pkRows.Next() {
			// We need to scan all columns from SHOW PRIMARY KEYS output
			// The column_name is what we're interested in
			var createdOn, databaseName, schemaName, tableName, columnName sql.NullString
			var keySequence sql.NullInt64
			var constraintName, comment sql.NullString

			if err := pkRows.Scan(&createdOn, &databaseName, &schemaName, &tableName,
				&columnName, &keySequence, &constraintName, &comment); err != nil {
				// If scanning fails, just skip primary key detection
				break
			}

			if columnName.Valid && columnName.String != "" {
				if col, exists := columnMap[columnName.String]; exists {
					col.PrimaryKey = true
				}
			}
		}
	}
	// If SHOW PRIMARY KEYS fails, we just continue without primary key information

	return columns, nil
}

func (c Connector) GuessColumnType(sqlType string) model.ColumnType {
	upperType := strings.ToUpper(sqlType)

	// Array types
	if strings.Contains(upperType, "ARRAY") {
		return model.TypeArray
	}

	// Object types
	if strings.Contains(upperType, "OBJECT") || strings.Contains(upperType, "VARIANT") {
		return model.TypeObject
	}

	// String types
	switch upperType {
	case "VARCHAR", "CHAR", "CHARACTER", "STRING", "TEXT", "BINARY", "VARBINARY":
		return model.TypeString
	}

	// Numeric types
	switch upperType {
	case "NUMBER", "DECIMAL", "NUMERIC", "FLOAT", "FLOAT4", "FLOAT8", "DOUBLE", "REAL":
		return model.TypeNumber
	}

	// Integer types
	switch upperType {
	case "INT", "INTEGER", "BIGINT", "SMALLINT", "TINYINT", "BYTEINT":
		return model.TypeInteger
	}

	// Boolean type
	switch upperType {
	case "BOOLEAN":
		return model.TypeBoolean
	}

	// Date/Time types
	switch upperType {
	case "DATE", "TIME", "DATETIME", "TIMESTAMP", "TIMESTAMP_LTZ", "TIMESTAMP_NTZ", "TIMESTAMP_TZ":
		return model.TypeDatetime
	}

	// Check for NUMBER with precision
	if strings.HasPrefix(upperType, "NUMBER(") {
		if strings.Contains(upperType, ",") {
			// NUMBER with decimal places (e.g., NUMBER(10,2))
			return model.TypeNumber
		} else {
			// NUMBER without decimal places (e.g., NUMBER(10))
			return model.TypeInteger
		}
	}

	// Default to string for unknown types
	return model.TypeString
}

func (c Connector) InferResultColumns(ctx context.Context, query string) ([]model.ColumnSchema, error) {
	return c.base.InferResultColumns(ctx, query, &c)
}

// InferQuery implements TypeGuesser interface for Snowflake
func (c Connector) InferQuery(ctx context.Context, query string) ([]model.ColumnSchema, error) {
	return c.base.InferResultColumns(ctx, query, &c)
}
