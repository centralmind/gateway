package bigquery

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cloud.google.com/go/bigquery"
	"github.com/centralmind/gateway/castx"
	"github.com/centralmind/gateway/connectors"
	"github.com/centralmind/gateway/logger"
	"github.com/centralmind/gateway/model"
	"golang.org/x/xerrors"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	"gopkg.in/yaml.v3"
)

//go:embed readme.md
var docString string

func init() {
	connectors.Register(func(cfg Config) (connectors.Connector, error) {
		var opts []option.ClientOption

		// If connection string is provided, try to parse it as JSON
		if cfg.ConnString != "" {
			var connConfig struct {
				ProjectID   string `json:"project_id"`
				Dataset     string `json:"dataset"`
				Credentials string `json:"credentials"`
				Endpoint    string `json:"endpoint"`
			}

			if err := json.Unmarshal([]byte(cfg.ConnString), &connConfig); err == nil {
				// If successful, update the config fields
				if connConfig.ProjectID != "" {
					cfg.ProjectID = connConfig.ProjectID
				}
				if connConfig.Dataset != "" {
					cfg.Dataset = connConfig.Dataset
				}
				if connConfig.Credentials != "" {
					cfg.Credentials = connConfig.Credentials
				}
				if connConfig.Endpoint != "" {
					cfg.Endpoint = connConfig.Endpoint
				}
			}
		}

		if cfg.Credentials != "" && cfg.Credentials != "{}" {
			credentialsFile := filepath.Join(logger.DefaultLogDir(), "bigquery-credentials.json")
			if err := os.WriteFile(credentialsFile, []byte(cfg.Credentials), 0600); err != nil {
				return nil, xerrors.Errorf("unable to write credentials file: %w", err)
			}
			opts = append(opts, option.WithCredentialsFile(credentialsFile))
		}

		if cfg.Endpoint != "" {
			opts = append(
				opts,
				option.WithEndpoint(cfg.Endpoint),
				option.WithoutAuthentication(),
			)
		}

		ctx := context.Background()
		client, err := bigquery.NewClient(ctx, cfg.ProjectID, opts...)
		if err != nil {
			return nil, xerrors.Errorf("failed to create client: %w", err)
		}

		return &Connector{
			config: cfg,
			client: client,
		}, nil
	})
}

type Config struct {
	ProjectID   string `json:"project_id" yaml:"project_id"`
	Dataset     string `json:"dataset" yaml:"dataset"`
	Credentials string `json:"credentials" yaml:"credentials"`
	Endpoint    string `yaml:"endpoint"`
	ConnString  string `yaml:"conn_string"`
	IsReadonly  bool   `yaml:"is_readonly"`
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
	return []string{
		"Do not include limit / offset as parameters",
	}
}

func (c Config) Type() string {
	return "bigquery"
}

func (c Config) Doc() string {
	return docString
}

type Connector struct {
	config Config
	client *bigquery.Client
}

func (c *Connector) Config() connectors.Config {
	return c.config
}

func (c *Connector) Sample(ctx context.Context, table model.Table) ([]map[string]any, error) {
	q := c.client.Query(fmt.Sprintf("SELECT * FROM `%s.%s.%s` LIMIT 5",
		c.config.ProjectID, c.config.Dataset, table.Name))

	it, err := q.Read(ctx)
	if err != nil {
		return nil, xerrors.Errorf("error executing query: %w", err)
	}

	var results []map[string]any
	for {
		var row map[string]bigquery.Value
		err := it.Next(&row)
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, xerrors.Errorf("error reading row: %w", err)
		}

		// Convert bigquery.Value to regular interface{}
		converted := make(map[string]interface{})
		for k, v := range row {
			converted[k] = v
		}
		results = append(results, converted)
	}

	return results, nil
}

func (c *Connector) Discovery(ctx context.Context, tablesList []string) ([]model.Table, error) {
	// Create a map for quick lookups if tablesList is provided
	tableSet := make(map[string]bool)
	if len(tablesList) > 0 {
		for _, table := range tablesList {
			tableSet[table] = true
		}
	}

	it := c.client.Dataset(c.config.Dataset).Tables(ctx)

	var tables []model.Table
	for {
		tbl, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, xerrors.Errorf("failed to list tables: %w", err)
		}

		// Skip tables not in the list if a list was provided
		if len(tablesList) > 0 && !tableSet[tbl.TableID] {
			continue
		}

		// Get the table metadata to access its schema
		meta, err := tbl.Metadata(ctx)
		if err != nil {
			return nil, xerrors.Errorf("failed to get table metadata: %w", err)
		}

		// Convert BigQuery schema to our model
		var columns []model.ColumnSchema
		for _, field := range meta.Schema {
			columns = append(columns, model.ColumnSchema{
				Name: field.Name,
				Type: c.GuessColumnType(string(field.Type)),
			})
		}

		// Get row count using approximate statistics
		var rowCount int
		if meta.NumRows > 0 {
			rowCount = int(meta.NumRows)
		} else {
			// If statistics not available, do a count query
			q := c.client.Query(fmt.Sprintf("SELECT COUNT(*) as count FROM `%s.%s.%s`",
				c.config.ProjectID, c.config.Dataset, tbl.TableID))

			job, err := q.Run(ctx)
			if err != nil {
				return nil, xerrors.Errorf("failed to run count query: %w", err)
			}

			status, err := job.Wait(ctx)
			if err != nil {
				return nil, xerrors.Errorf("failed to wait for count query: %w", err)
			}

			if status.Err() != nil {
				return nil, xerrors.Errorf("count query failed: %w", status.Err())
			}

			iter, err := job.Read(ctx)
			if err != nil {
				return nil, xerrors.Errorf("failed to read count query results: %w", err)
			}

			var row struct{ Count int64 }
			if err := iter.Next(&row); err != nil {
				return nil, xerrors.Errorf("failed to get count: %w", err)
			}

			rowCount = int(row.Count)
		}

		tables = append(tables, model.Table{
			Name:     tbl.TableID,
			Columns:  columns,
			RowCount: rowCount,
		})
	}

	return tables, nil
}

func (c *Connector) Ping(ctx context.Context) error {
	// Simple metadata call to check connection
	_, err := c.client.Dataset(c.config.Dataset).Metadata(ctx)
	return err
}

func (c *Connector) Query(ctx context.Context, endpoint model.Endpoint, params map[string]any) ([]map[string]any, error) {
	processed, err := castx.ParamsE(endpoint, params)
	if err != nil {
		return nil, xerrors.Errorf("unable to process params: %w", err)
	}
	for name, value := range processed {
		if name == "offset" || name == "limit" { // these 2 are special
			endpoint.Query = strings.ReplaceAll(endpoint.Query, "@"+name, fmt.Sprintf("%v", value))
		}
	}

	// Create query with parameters
	q := c.client.Query(endpoint.Query)

	// Set query parameters
	for name, value := range processed {
		if name == "offset" || name == "limit" { // these 2 are special
			continue
		}
		q.Parameters = append(q.Parameters, bigquery.QueryParameter{
			Name:  name,
			Value: value,
		})
	}

	// Run query
	it, err := q.Read(ctx)
	if err != nil {
		return nil, xerrors.Errorf("error executing query: %w", err)
	}

	var results []map[string]any
	for {
		var row map[string]bigquery.Value
		err := it.Next(&row)
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, xerrors.Errorf("error reading row: %w", err)
		}

		// Convert bigquery.Value to regular interface{}
		converted := make(map[string]interface{})
		for k, v := range row {
			converted[k] = v
		}
		results = append(results, converted)
	}

	return results, nil
}

func (c *Connector) GuessColumnType(sqlType string) model.ColumnType {
	switch sqlType {
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
	// Create a dry run job to get schema without executing the query
	query = strings.ReplaceAll(query, "@limit", "1")
	query = strings.ReplaceAll(query, "@offset", "0")
	if !strings.HasPrefix(strings.ToLower(query), "select") {
		return nil, nil
	}
	q := c.client.Query(query)
	q.DryRun = true

	job, err := q.Run(ctx)
	if err != nil {
		return nil, xerrors.Errorf("error in dry run: %w", err)
	}

	status := job.LastStatus()
	if status.Statistics == nil || status.Statistics.Details == nil {
		return nil, xerrors.New("no schema information available")
	}

	details, ok := status.Statistics.Details.(*bigquery.QueryStatistics)
	if !ok {
		return nil, xerrors.New("unexpected statistics type")
	}

	if details.Schema == nil {
		return nil, xerrors.New("no schema information available")
	}

	columns := make([]model.ColumnSchema, 0)
	for _, field := range details.Schema {
		columns = append(columns, model.ColumnSchema{
			Name: field.Name,
			Type: c.GuessColumnType(string(field.Type)),
		})
	}

	return columns, nil
}

func (c *Connector) InferQuery(ctx context.Context, query string) ([]model.ColumnSchema, error) {
	return c.InferResultColumns(ctx, query)
}

// Close releases any resources held by the connector
func (c *Connector) Close() error {
	return c.client.Close()
}
