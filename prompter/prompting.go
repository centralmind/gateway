package prompter

import (
	_ "embed"
	"fmt"
	"strings"

	"github.com/centralmind/gateway/connectors"
	gw_model "github.com/centralmind/gateway/model"
	"gopkg.in/yaml.v3"
)

var (
	//go:embed endpoints_schema.json
	apiConfigSchema []byte

	endpointsPrompt = `
!Important rules:
	- The final output must contain *only valid single JSON* with no additional commentary, explanations, or markdown formatting!
	- The JSON configuration must strictly adhere to the provided JSON schema, including all required fields.
	- You must always match all parameter names. Ensure you use the same name for the same entity, especially in HTTP routes. Use full names for parameters in HTTP routes, such as "userId" instead of "id".
	- Description of API endpoints should also have an example, to help chatbot to use it.
	- All SQL queries must be Pure SQL that will be used in golang SQLx on top of database - {database_type} and be fully parameterized (using named parameters) to prevent SQL injection.
	- Do not generate output schema for endpoints.
	- All SQL queries must be verified that they will not return array of data where expected one item.
	- SQL queries should be optimized for {database_type} and use appropriate indexes.
	- Endpoints that return lists must include pagination parameters (offset and limit).
	- Consistent Endpoint Definitions: Each table defined in the DDL should have corresponding endpoints as specified by the JSON schema, including method, path, description, SQL query, and parameters.
	- If some entity requires pagination, there should be separate API that calculates total_count, so pagination can be queried
	- For Postgres, use all table names and column names in double quotes, e.g., "table_name" and "column_name". 
	- If a schema is specified in the table name (format: schema.table), use it in your queries appropriately for the database type. For Postgres, this would be "schema"."table_name".
`
	piiReportPrompt = `
!Important rules:
	- The final output must contain *only valid single JSON* with no additional commentary, explanations, or markdown formatting!
	- The JSON configuration must strictly adhere to the provided JSON schema, including all required fields.
	- Analyze endpoints generated against endpoint definitions.
	- Detect where is PII or sensitive data located in data samples
`
)

func DiscoverEndpointsPrompt(connector connectors.Connector, extraPrompt string, tables []TableData, schema string) string {
	res := "I need a config for an automatic API that will be used by another AI bot or LLMs..."
	res += "\n"
	res += strings.ReplaceAll(endpointsPrompt, "{database_type}", connector.Config().Type())
	for _, extraPrompt := range connector.Config().ExtraPrompt() {
		res += res + "	-" + extraPrompt + "\n"
	}
	res += "\n" + string(apiConfigSchema) + "\n" + extraPrompt + "\n\n"
	res += TablesPrompt(tables, schema)

	return res
}

func TablesPrompt(tables []TableData, schema string) string {
	var res string
	for _, table := range tables {
		// Apply schema to table name if schema is provided and not empty
		var tableName string

		if !strings.Contains(table.Name, ".") {
			if schema != "" {
				// Qualify the table name with schema
				tableName = fmt.Sprintf("%s.%s", schema, table.Name)
			} else {
				// Use the table name as is
				tableName = fmt.Sprintf("%s.%s", "public", table.Name)
			}
		} else {
			tableName = table.Name
		}

		res += fmt.Sprintf(`
<%[1]s number_columns=%[5]v number_rows=%[6]v>
schema:
%[2]s
---
data_sample:
%[3]s
</%[1]s>

`, tableName, Yamlify(table.Columns), Yamlify(table.Sample), len(table.Sample), len(table.Columns), table.RowCount)
	}
	return res
}

// PromptColumnSchema is used specifically for generating prompts,
// omitting sensitive fields like PII flag
type PromptColumnSchema struct {
	Name       string `yaml:"name"`
	Type       string `yaml:"type"`
	PrimaryKey bool   `yaml:"primary_key,omitempty"`
}

func columnToPromptSchema(col gw_model.ColumnSchema) PromptColumnSchema {
	return PromptColumnSchema{
		Name:       col.Name,
		Type:       string(col.Type),
		PrimaryKey: col.PrimaryKey,
	}
}

func Yamlify(sample any) string {
	// Convert ColumnSchema to PromptColumnSchema if needed
	if columns, ok := sample.([]gw_model.ColumnSchema); ok {
		promptColumns := make([]PromptColumnSchema, len(columns))
		for i, col := range columns {
			promptColumns[i] = columnToPromptSchema(col)
		}
		sample = promptColumns
	}
	raw, _ := yaml.Marshal(sample)
	return string(raw)
}

type TableData struct {
	Columns  []gw_model.ColumnSchema
	Name     string
	Sample   []map[string]any
	RowCount int
}

// SchemaFromConfig resolve schema from database config if it exists
func SchemaFromConfig(config connectors.Config) string {
	schema := ""

	// Try to parse the config to get the schema for any database type
	var generalConfig struct {
		Schema    string `yaml:"schema"`
		ProjectID string `json:"project_id" yaml:"project_id"`
		Dataset   string `json:"dataset" yaml:"dataset"`
	}

	if err := yaml.Unmarshal([]byte(Yamlify(config)), &generalConfig); err == nil {
		if generalConfig.Schema != "" {
			schema = generalConfig.Schema
		}
	}

	// Handle special case for PostgreSQL where public is the default schema
	if config.Type() == "postgres" && schema == "" {
		schema = "public"
	}

	if config.Type() == "bigquery" {
		schema = fmt.Sprintf("%s.%s", generalConfig.ProjectID, generalConfig.Dataset)
	}

	if config.Type() == "duckdb" && schema == "" {
		schema = "main"
	}

	return schema
}
