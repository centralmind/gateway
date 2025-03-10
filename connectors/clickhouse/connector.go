package clickhouse

import (
	"context"
	_ "embed"
	"fmt"
	"strings"

	_ "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/centralmind/gateway/castx"
	"github.com/centralmind/gateway/connectors"
	"github.com/centralmind/gateway/model"
	"github.com/jmoiron/sqlx"
	"golang.org/x/xerrors"
)

//go:embed readme.md
var docString string

func init() {
	connectors.Register(func(cfg Config) (connectors.Connector, error) {
		dsn := cfg.MakeDSN()
		db, err := sqlx.Open("clickhouse", dsn)
		if err != nil {
			return nil, xerrors.Errorf("unable to open ClickHouse db: %w", err)
		}
		return &Connector{
			config: cfg,
			db:     db,
			base:   &connectors.BaseConnector{DB: db},
		}, nil
	})
}

type Config struct {
	Host     string   // Single host
	Hosts    []string // Multiple hosts
	Database string
	User     string
	Password string
	Port     int
	Secure   bool
}

func (c Config) MakeDSN() string {
	protocol := "http"
	if c.Secure {
		protocol = "https"
	}

	host := c.Host
	// If no single host is specified but we have hosts array, use the first one
	if host == "" && len(c.Hosts) > 0 {
		host = c.Hosts[0]
	}

	// Format as protocol://user:password@host:port/database
	return fmt.Sprintf("%s://%s:%s@%s:%d/%s", protocol, c.User, c.Password, host, c.Port, c.Database)
}

func (c Config) Type() string {
	return "clickhouse"
}

func (c Config) Doc() string {
	return docString
}

type Connector struct {
	config Config
	db     *sqlx.DB
	base   *connectors.BaseConnector
}

func (c Connector) Sample(ctx context.Context, table model.Table) ([]map[string]any, error) {
	rows, err := c.db.QueryxContext(ctx, fmt.Sprintf("SELECT * FROM %s LIMIT 5", table.Name))
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

func (c Connector) Discovery(ctx context.Context) ([]model.Table, error) {
	rows, err := c.db.QueryContext(ctx, fmt.Sprintf("SHOW TABLES FROM %s", c.config.Database))
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
		columns, err := c.LoadsColumns(ctx, tableName)
		if err != nil {
			return nil, err
		}

		// Get the total row count for this table
		var rowCount int
		countQuery := fmt.Sprintf("SELECT COUNT(*) FROM `%s`.`%s`", c.config.Database, tableName)
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
	rows, err := c.db.NamedQueryContext(ctx, endpoint.Query, processed)
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
	rows, err := c.db.QueryContext(
		ctx,
		`SELECT 
			name,
			type,
			is_in_primary_key as is_primary_key
		FROM system.columns 
		WHERE table = ? 
		AND database = ?`,
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

// GuessColumnType implements TypeGuesser interface for ClickHouse
func (c *Connector) GuessColumnType(sqlType string) model.ColumnType {
	// ClickHouse types are case-sensitive
	// Array types (check first as they contain other type names)
	if strings.Contains(sqlType, "Array") || strings.Contains(sqlType, "Nested") || strings.Contains(sqlType, "Tuple") {
		return model.TypeArray
	}

	// Object types
	switch sqlType {
	case "JSON", "Object('json')":
		return model.TypeObject
	}

	// String types
	switch sqlType {
	case "String", "UUID", "IPv4", "IPv6", "Enum8", "Enum16":
		return model.TypeString
	}
	if strings.HasPrefix(sqlType, "FixedString") {
		return model.TypeString
	}

	// Numeric types
	switch {
	case strings.HasPrefix(sqlType, "Float32"), strings.HasPrefix(sqlType, "Float64"),
		strings.HasPrefix(sqlType, "Decimal"), strings.HasPrefix(sqlType, "Decimal32"),
		strings.HasPrefix(sqlType, "Decimal64"), strings.HasPrefix(sqlType, "Decimal128"):
		return model.TypeNumber
	}

	// Integer types
	switch sqlType {
	case "Int8", "Int16", "Int32", "Int64", "UInt8", "UInt16", "UInt32", "UInt64":
		return model.TypeInteger
	}

	// Boolean type
	if sqlType == "Bool" {
		return model.TypeBoolean
	}

	// Date/Time types
	switch {
	case sqlType == "Date", strings.HasPrefix(sqlType, "DateTime"):
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
