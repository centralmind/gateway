package bigquery

import (
	"context"
	_ "embed"
	"fmt"
	"strings"

	"github.com/centralmind/gateway/castx"
	"github.com/centralmind/gateway/connectors"
	"github.com/centralmind/gateway/model"
	"github.com/jmoiron/sqlx"
	"golang.org/x/xerrors"
	_ "gorm.io/driver/bigquery/driver"
)

//go:embed readme.md
var docString string

func init() {
	connectors.Register(func(cfg Config) (connectors.Connector, error) {
		// Format: bigquery://project/location/dataset?credentials=base64_credentials
		dsn := fmt.Sprintf("bigquery://%s/%s?1=1&credentials=%s",
			cfg.ProjectID,
			cfg.Dataset,
			cfg.Credentials,
		)
		if cfg.Endpoint != "" {
			dsn = fmt.Sprintf("%s&endpoint=%s&disable_auth=true", dsn, cfg.Endpoint)
		}

		db, err := sqlx.Open("bigquery", dsn)
		if err != nil {
			return nil, xerrors.Errorf("unable to create BigQuery connection: %w", err)
		}

		return &Connector{
			config: cfg,
			db:     db,
			base:   &connectors.BaseConnector{DB: db},
		}, nil
	})
}

type Config struct {
	ProjectID   string `json:"project_id"`
	Dataset     string `json:"dataset"`
	Credentials string `json:"credentials"`
	Endpoint    string `yaml:"endpoint"`
}

func (c Config) Type() string {
	return "bigquery"
}

func (c Config) Doc() string {
	return docString
}

type Connector struct {
	config Config
	db     *sqlx.DB
	base   *connectors.BaseConnector
}

func (c *Connector) Sample(ctx context.Context, table model.Table) ([]map[string]any, error) {
	query := fmt.Sprintf("SELECT * FROM `%s.%s.%s` LIMIT 5", c.config.ProjectID, c.config.Dataset, table.Name)
	rows, err := c.db.QueryxContext(ctx, query)
	if err != nil {
		return nil, xerrors.Errorf("unable to execute query: %w", err)
	}
	defer rows.Close()

	var results []map[string]any
	for rows.Next() {
		row := make(map[string]interface{})
		if err := rows.MapScan(row); err != nil {
			return nil, xerrors.Errorf("error scanning row: %w", err)
		}
		results = append(results, row)
	}

	if err = rows.Err(); err != nil {
		return nil, xerrors.Errorf("error iterating rows: %w", err)
	}

	return results, nil
}

func (c *Connector) Discovery(ctx context.Context) ([]model.Table, error) {
	query := fmt.Sprintf(`
		SELECT 
			table_name,
			column_name,
			data_type,
			is_nullable
		FROM %s.INFORMATION_SCHEMA.COLUMNS
		ORDER BY table_name, ordinal_position`,
		c.config.Dataset)

	rows, err := c.db.QueryxContext(ctx, query)
	if err != nil {
		return nil, xerrors.Errorf("unable to query schema: %w", err)
	}
	defer rows.Close()

	tables := make(map[string]*model.Table)
	for rows.Next() {
		var tableName, columnName, dataType, isNullable string
		if err := rows.Scan(&tableName, &columnName, &dataType, &isNullable); err != nil {
			return nil, xerrors.Errorf("error scanning row: %w", err)
		}

		table, ok := tables[tableName]
		if !ok {
			table = &model.Table{
				Name:    tableName,
				Columns: []model.ColumnSchema{},
			}
			tables[tableName] = table
		}

		table.Columns = append(table.Columns, model.ColumnSchema{
			Name:       columnName,
			Type:       c.GuessColumnType(dataType),
			PrimaryKey: false, // BigQuery doesn't have traditional primary keys
		})
	}

	if err = rows.Err(); err != nil {
		return nil, xerrors.Errorf("error iterating rows: %w", err)
	}

	// Convert map to slice
	result := make([]model.Table, 0, len(tables))
	for _, table := range tables {
		// Get row count for the table
		var count int
		countQuery := fmt.Sprintf("SELECT COUNT(*) FROM `%s.%s.%s`", c.config.ProjectID, c.config.Dataset, table.Name)
		err := c.db.QueryRowxContext(ctx, countQuery).Scan(&count)
		if err != nil {
			return nil, xerrors.Errorf("unable to get row count for table %s: %w", table.Name, err)
		}
		table.RowCount = count
		result = append(result, *table)
	}

	return result, nil
}

func (c *Connector) Ping(ctx context.Context) error {
	return c.db.PingContext(ctx)
}

func (c *Connector) Query(ctx context.Context, endpoint model.Endpoint, params map[string]any) ([]map[string]any, error) {
	processed, err := castx.ParamsE(endpoint, params)
	if err != nil {
		return nil, xerrors.Errorf("unable to process params: %w", err)
	}

	// Convert params to []interface{} for sql.DB
	args := make([]interface{}, 0, len(processed))
	for _, v := range processed {
		args = append(args, v)
	}

	rows, err := c.db.QueryxContext(ctx, endpoint.Query, args...)
	if err != nil {
		return nil, xerrors.Errorf("unable to execute query: %w", err)
	}
	defer rows.Close()

	var results []map[string]any
	for rows.Next() {
		row := make(map[string]interface{})
		if err := rows.MapScan(row); err != nil {
			return nil, xerrors.Errorf("error scanning row: %w", err)
		}
		results = append(results, row)
	}

	if err = rows.Err(); err != nil {
		return nil, xerrors.Errorf("error iterating rows: %w", err)
	}

	return results, nil
}

func (c *Connector) GuessColumnType(sqlType string) model.ColumnType {
	switch strings.ToUpper(sqlType) {
	case "STRING", "BYTES":
		return model.TypeString
	case "INTEGER", "INT64":
		return model.TypeInteger
	case "FLOAT", "FLOAT64", "NUMERIC", "BIGNUMERIC":
		return model.TypeNumber
	case "BOOLEAN", "BOOL":
		return model.TypeBoolean
	case "TIMESTAMP", "DATE", "TIME", "DATETIME":
		return model.TypeDatetime
	case "RECORD", "STRUCT":
		return model.TypeObject
	case "ARRAY":
		return model.TypeArray
	default:
		return model.TypeString
	}
}

func (c *Connector) InferResultColumns(ctx context.Context, query string) ([]model.ColumnSchema, error) {
	// Execute the query with LIMIT 0 to get column information without fetching data
	rows, err := c.db.QueryxContext(ctx, fmt.Sprintf("SELECT * FROM (%s) LIMIT 0", query))
	if err != nil {
		return nil, xerrors.Errorf("unable to execute query: %w", err)
	}
	defer rows.Close()

	types, err := rows.ColumnTypes()
	if err != nil {
		return nil, xerrors.Errorf("unable to get column types: %w", err)
	}

	columns := make([]model.ColumnSchema, len(types))
	for i, t := range types {
		columns[i] = model.ColumnSchema{
			Name: t.Name(),
			Type: c.GuessColumnType(t.DatabaseTypeName()),
		}
	}

	return columns, nil
}

func (c *Connector) InferQuery(ctx context.Context, query string) ([]model.ColumnSchema, error) {
	return c.InferResultColumns(ctx, query)
}
