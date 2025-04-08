package oracle

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
	_ "github.com/sijms/go-ora/v2"
	"golang.org/x/xerrors"
)

func init() {
	connectors.Register[Config](func(cfg Config) (connectors.Connector, error) {
		connStr := cfg.ConnectionString()

		db, err := sqlx.Connect("oracle", connStr)
		if err != nil {
			return nil, fmt.Errorf("unable to connect to oracle: %v", err)
		}
		return &Connector{
			config: cfg,
			db:     db,
			base:   &connectors.BaseConnector{DB: db},
		}, nil
	})
}

// Connector implements the connectors.Connector interface for Oracle Database
type Connector struct {
	config Config
	db     *sqlx.DB
	base   *connectors.BaseConnector
}

func (c Connector) Config() connectors.Config {
	return c.config
}

// GuessColumnType implements TypeGuesser interface for Oracle
func (c *Connector) GuessColumnType(sqlType string) model.ColumnType {
	upperType := strings.ToUpper(sqlType)

	// String types
	switch upperType {
	case "VARCHAR", "VARCHAR2", "CHAR", "NCHAR", "NVARCHAR2", "CLOB", "NCLOB",
		"LONG", "ROWID", "UROWID":
		return model.TypeString
	}

	// Numeric types
	switch upperType {
	case "NUMBER", "FLOAT", "BINARY_FLOAT", "BINARY_DOUBLE":
		return model.TypeNumber
	}

	// Integer types (special case of NUMBER)
	if strings.Contains(upperType, "NUMBER(") && !strings.Contains(upperType, ",") {
		return model.TypeInteger
	}

	// Date/Time types
	switch upperType {
	case "DATE", "TIMESTAMP", "TIMESTAMP WITH TIME ZONE", "TIMESTAMP WITH LOCAL TIME ZONE":
		return model.TypeDatetime
	}

	// Binary types
	switch upperType {
	case "BLOB", "BFILE", "RAW", "LONG RAW":
		return model.TypeString
	}

	// Default to string for unknown types
	return model.TypeString
}

func (c Connector) Sample(ctx context.Context, table model.Table) ([]map[string]any, error) {
	// Create schema-qualified table name
	qualifiedTableName := fmt.Sprintf("%s.%s", c.config.Schema, table.Name)

	tx, err := c.db.BeginTxx(ctx, &sql.TxOptions{
		ReadOnly: true,
	})
	if err != nil {
		return nil, xerrors.Errorf("BeginTx failed with error: %w", err)
	}
	defer tx.Commit()

	rows, err := tx.NamedQuery(fmt.Sprintf("SELECT * FROM %s WHERE ROWNUM <= 5", qualifiedTableName), map[string]any{})
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
			// Oracle table names are typically uppercase
			tableSet[strings.ToUpper(table)] = true
		}
	}

	var query string
	var args []interface{}

	if len(tablesList) > 0 {
		// If specific tables are requested, build a query with IN clause
		placeholders := make([]string, len(tablesList))
		args = make([]interface{}, len(tablesList))

		for i, table := range tablesList {
			placeholders[i] = ":" + strconv.Itoa(i+1)
			args[i] = strings.ToUpper(table) // Oracle table names are typically stored uppercase
		}

		query = fmt.Sprintf(`
			SELECT table_name 
			FROM user_tables 
			WHERE table_name IN (%s)`, strings.Join(placeholders, ","))
	} else {
		// Otherwise, query all tables
		query = `SELECT table_name FROM user_tables`
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
			return nil, err
		}

		columns, err := c.LoadsColumns(ctx, tableName)
		if err != nil {
			return nil, err
		}

		// Get the total row count for this table
		var rowCount int
		countQuery := fmt.Sprintf("SELECT COUNT(*) FROM \"%s\"", tableName)
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
	rows, err := c.db.QueryContext(ctx, "SELECT 1 FROM DUAL")
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

	// Convert parameters and build ordered parameter list
	paramNames := make([]string, 0)
	paramValues := make([]interface{}, 0)

	// Process parameters and collect them in order
	for _, param := range endpoint.Params {
		if value, ok := processed[param.Name]; ok {
			paramNames = append(paramNames, ":"+param.Name)

			switch param.Type {
			case "integer":
				if strVal, ok := value.(string); ok {
					if intVal, err := strconv.Atoi(strVal); err == nil {
						paramValues = append(paramValues, intVal)
						continue
					}
				}
				paramValues = append(paramValues, value)
			case "number":
				if strVal, ok := value.(string); ok {
					if floatVal, err := strconv.ParseFloat(strVal, 64); err == nil {
						paramValues = append(paramValues, floatVal)
						continue
					}
				}
				paramValues = append(paramValues, value)
			case "boolean":
				if strVal, ok := value.(string); ok {
					if boolVal, err := strconv.ParseBool(strVal); err == nil {
						paramValues = append(paramValues, boolVal)
						continue
					}
				}
				paramValues = append(paramValues, value)
			default:
				paramValues = append(paramValues, value)
			}
		}
	}

	// Replace named parameters with numbered ones
	query := endpoint.Query
	for i, name := range paramNames {
		query = strings.Replace(query, name, fmt.Sprintf(":%d", i+1), -1)
	}

	tx, err := c.db.BeginTxx(ctx, &sql.TxOptions{
		ReadOnly: c.Config().Readonly(),
	})
	if err != nil {
		return nil, xerrors.Errorf("BeginTx failed with error: %w", err)
	}
	defer tx.Commit()

	// Execute query with numbered parameters
	rows, err := tx.Queryx(query, paramValues...)
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
			c.COLUMN_NAME,
			c.DATA_TYPE,
			c.NULLABLE,
			CASE WHEN p.COLUMN_NAME IS NOT NULL THEN 1 ELSE 0 END as IS_PRIMARY_KEY
		FROM ALL_TAB_COLUMNS c
		LEFT JOIN (
			SELECT col.COLUMN_NAME
			FROM ALL_CONSTRAINTS cons
			JOIN ALL_CONS_COLUMNS col
				ON cons.CONSTRAINT_NAME = col.CONSTRAINT_NAME
			WHERE cons.CONSTRAINT_TYPE = 'P'
				AND col.TABLE_NAME = :1
				AND cons.OWNER = :2
		) p ON c.COLUMN_NAME = p.COLUMN_NAME
		WHERE c.TABLE_NAME = :1
		AND c.OWNER = :2`,
		tableName, c.config.Schema,
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
