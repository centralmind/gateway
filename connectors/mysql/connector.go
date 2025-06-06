package mysql

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"strings"

	"github.com/centralmind/gateway/connectors"

	"github.com/centralmind/gateway/castx"
	"github.com/centralmind/gateway/model"
	"github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"
)

//go:embed readme.md
var docString string

func init() {
	connectors.Register(func(cfg Config) (connectors.Connector, error) {
		dsn, err := cfg.MakeDSN()
		if err != nil {
			return nil, xerrors.Errorf("unable to prepare mysql config: %w", err)
		}
		db, err := sqlx.Open("mysql", dsn)
		if err != nil {
			return nil, xerrors.Errorf("unable to open mysql db: %w", err)
		}
		return &Connector{
			config: cfg,
			db:     db,
			base:   &connectors.BaseConnector{DB: db},
		}, nil
	})
}

type Config struct {
	Host       string
	Database   string
	User       string
	Password   string
	Port       int
	TLSConfig  string
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
	cfg := mysql.Config{
		User:                 c.User,
		Passwd:               c.Password,
		Net:                  "tcp",
		Addr:                 fmt.Sprintf("%s:%d", c.Host, c.Port),
		DBName:               c.Database,
		AllowNativePasswords: true,
		ParseTime:            true,
		TLSConfig:            c.TLSConfig,
	}
	return cfg.FormatDSN(), nil
}

func (c Config) Type() string {
	return "mysql"
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
	tx, err := c.base.DB.BeginTxx(ctx, &sql.TxOptions{
		ReadOnly: c.Config().Readonly(),
	})
	if err != nil {
		return nil, xerrors.Errorf("BeginTx failed with error: %w", err)
	}
	rows, err := tx.QueryxContext(ctx, fmt.Sprintf("SELECT * FROM %s LIMIT 5", table.Name))
	if err != nil {
		return nil, xerrors.Errorf("unable to query db: %w", err)
	}
	defer rows.Close()

	res := make([]map[string]any, 0, 5)
	for rows.Next() {
		row := make(map[string]any)
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
			placeholders[i] = "?"
			args[i] = table
		}
		query = fmt.Sprintf("SHOW TABLES WHERE Tables_in_%s IN (%s)",
			c.config.Database, strings.Join(placeholders, ","))
	} else {
		// Otherwise, query all tables
		query = "SHOW TABLES"
	}

	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tables []model.Table
	for rows.Next() {
		var tableName string
		if err := rows.Scan(&tableName); err != nil {
			return nil, err
		}

		// Skip tables not in the list if a list was provided
		if len(tablesList) > 0 && !tableSet[tableName] {
			continue
		}

		columns, err := c.LoadsColumns(ctx, tableName)
		if err != nil {
			return nil, err
		}

		// Get the total row count for this table
		var rowCount int
		countQuery := fmt.Sprintf("SELECT COUNT(*) FROM `%s`", tableName)
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
	return c.db.PingContext(ctx)
}

func (c Connector) Query(ctx context.Context, endpoint model.Endpoint, params map[string]any) ([]map[string]any, error) {
	processed, err := castx.ParamsE(endpoint, params)
	if err != nil {
		return nil, xerrors.Errorf("unable to process params: %w", err)
	}
	tx, err := c.base.DB.BeginTxx(ctx, &sql.TxOptions{
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
		res = append(res, castx.Process(row))
	}
	return res, nil
}

func (c Connector) LoadsColumns(ctx context.Context, tableName string) ([]model.ColumnSchema, error) {
	tx, err := c.base.DB.BeginTxx(ctx, &sql.TxOptions{
		ReadOnly: c.Config().Readonly(),
	})
	if err != nil {
		return nil, xerrors.Errorf("BeginTx failed with error: %w", err)
	}
	defer tx.Commit()
	rows, err := tx.QueryContext(
		ctx,
		`SELECT 
			COLUMN_NAME, 
			DATA_TYPE,
			COLUMN_KEY = 'PRI' as is_primary_key
		FROM information_schema.columns 
		WHERE table_name = ? 
		AND table_schema = ?`,
		tableName, c.config.Database,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var columns []model.ColumnSchema
	for rows.Next() {
		var name, dataType string
		var isPrimaryKey bool
		if err := rows.Scan(&name, &dataType, &isPrimaryKey); err != nil {
			return nil, err
		}
		columns = append(columns, model.ColumnSchema{
			Name:       name,
			Type:       c.GuessColumnType(dataType),
			PrimaryKey: isPrimaryKey,
		})
	}
	return columns, nil
}

// GuessColumnType implements TypeGuesser interface for MySQL
func (c *Connector) GuessColumnType(sqlType string) model.ColumnType {
	upperType := strings.ToUpper(sqlType)

	// Set type (mapped to array)
	if strings.Contains(upperType, "SET") {
		return model.TypeArray
	}

	// Object types
	switch upperType {
	case "JSON":
		return model.TypeObject
	}

	// String types
	switch upperType {
	case "VARCHAR", "CHAR", "TEXT", "TINYTEXT", "MEDIUMTEXT", "LONGTEXT", "ENUM":
		return model.TypeString
	}

	// Numeric types
	switch upperType {
	case "DECIMAL", "NUMERIC", "FLOAT", "DOUBLE":
		return model.TypeNumber
	}

	// Integer types (except TINYINT(1) which is boolean)
	switch upperType {
	case "INT", "INTEGER", "BIGINT", "MEDIUMINT", "SMALLINT":
		return model.TypeInteger
	}

	// Special case for TINYINT(1) which MySQL uses for boolean
	if strings.Contains(upperType, "TINYINT(1)") {
		return model.TypeBoolean
	}
	// Regular TINYINT is treated as integer
	if strings.Contains(upperType, "TINYINT") {
		return model.TypeInteger
	}

	// Boolean type
	switch upperType {
	case "BOOLEAN", "BOOL":
		return model.TypeBoolean
	}

	// Date/Time types
	switch upperType {
	case "DATE", "TIME", "DATETIME", "TIMESTAMP", "YEAR":
		return model.TypeDatetime
	}

	// Default to string for unknown types
	return model.TypeString
}

// InferResultColumns returns column information for the given query
func (c *Connector) InferResultColumns(ctx context.Context, query string) ([]model.ColumnSchema, error) {
	return c.base.InferResultColumns(ctx, query, c)
}

// InferQuery implements the Connector interface
func (c *Connector) InferQuery(ctx context.Context, query string) ([]model.ColumnSchema, error) {
	return c.base.InferResultColumns(ctx, query, c)
}
