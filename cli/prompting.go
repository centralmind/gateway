package cli

import (
	"context"
	"fmt"
	"log"
	"strings"

	gw_model "github.com/centralmind/gateway/model"
	"github.com/centralmind/gateway/providers"
	"github.com/sirupsen/logrus"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"
)

var (
	discoverBasePrompt = `
!Important rules:
	- The most important: The final output must contain *only valid single JSON* with no additional commentary, explanations, or markdown formatting!
	- The JSON configuration must strictly adhere to the provided JSON schema, including all required fields.
	- You must always match all parameter names. Ensure you use the same name for the same entity, especially in HTTP routes. Use full names for parameters in HTTP routes, such as "userId" instead of "id".
	- Description of API endpoints should also have an example, to help chatbot to use it.
	- All descriptions and summary must not have any sensitive information/data from security point of view including database types, password and etc.
	- All SQL queries must be Pure SQL that will be used in golang SQLx on top of database - {database_type} and be fully parameterized (using named parameters) to prevent SQL injection.
	- Do not generate output schema for endpoints.
	- All SQL queries must be verified that they will not return array of data where expected one item.
	- SQL queries should be optimized for {database_type} and use appropriate indexes.
	- Endpoints that return lists must include pagination parameters (offset and limit).
	- Consistent Endpoint Definitions: Each table defined in the DDL should have corresponding endpoints as specified by the JSON schema, including method, path, description, SQL query, and parameters.
	- Sensitive Data Handling: If any columns contain sensitive or PII data like phone number, SSN, address, credit card etc, they must be flagged appropriately (e.g., using a "pii" flag).
	- Each Parameter in API endpoints may have default value taken from corresponded example rows, only if it's not PII or sensitive data
	- If some entity requires pagination, there should be separate API that calculates total_count, so pagination can be queried
	- For Postgres, use all table names and column names in double quotes, e.g., "table_name" and "column_name". 
	- If a schema is specified in the table name (format: schema.table), use it in your queries appropriately for the database type. For Postgres, this would be "schema"."table_name".
`
)

type DiscoverQueryParams struct {
	LLMLogFile    string
	Provider      string
	Endpoint      string
	APIKey        string
	Model         string
	MaxTokens     int
	Temperature   float32
	Reasoning     bool
	BedrockRegion string
	VertexRegion  string
	VertexProject string
}

type DiscoverQueryResponse struct {
	Config       *gw_model.Config
	Conversation *providers.ConversationResponse
	RawContent   string
	CostEstimate float64
}

func generateDiscoverPrompt(databaseType, extraPrompt string, tables []TableData, schema string) string {
	res := "I need a config for an automatic API that will be used by another AI bot or LLMs..."
	res += "\n"
	res += strings.ReplaceAll(discoverBasePrompt, "{database_type}", databaseType)
	res += "\n" + string(apiConfigSchema) + "\n" + extraPrompt + "\n\n"
	for _, table := range tables {
		// Apply schema to table name if schema is provided and not empty
		var tableName string

		if schema != "" {
			// Qualify the table name with schema
			tableName = fmt.Sprintf("%s.%s", schema, table.Name)
		} else {
			// Use the table name as is
			tableName = fmt.Sprintf("%s.%s", "public", table.Name)
		}

		res += fmt.Sprintf(`
<%[1]s number_columns=%[5]v number_rows=%[6]v>
schema:
%[2]s
---
data_sample:
%[3]s
</%[1]s>

`, tableName, yamlify(table.Columns), yamlify(table.Sample), len(table.Sample), len(table.Columns), table.RowCount)
	}

	return res
}

func makeDiscoverQuery(params DiscoverQueryParams, prompt string) (DiscoverQueryResponse, error) {
	provider, err := providers.NewModelProvider(providers.ModelProviderConfig{
		Name:            params.Provider,
		APIKey:          params.APIKey,
		Endpoint:        params.Endpoint,
		BedrockRegion:   params.BedrockRegion,
		VertexAIRegion:  params.VertexRegion,
		VertexAIProject: params.VertexProject,
	})

	if err != nil {
		log.Fatalf("Failed to initialize provider: %v", err)
	}

	logrus.Infof("Calling provider: %s", provider.GetName())

	done := make(chan bool)
	go startSpinner("Thinking. The process can take a few minutes to finish", done)

	request := &providers.ConversationRequest{
		Reasoning:    params.Reasoning,
		JsonResponse: true,
		System:       "You must always respond in pure JSON. No markdown, no comments, no explanations.",
		Messages: []providers.Message{
			{
				Role: providers.UserRole,
				Content: []providers.ContentBlock{
					&providers.ContentBlockText{
						Value: prompt,
					},
				},
			},
		},
		ModelId:   params.Model,
		MaxTokens: params.MaxTokens,
	}

	llmResponse, err := provider.Chat(context.Background(), request)
	if err != nil {
		log.Fatalf("Failed to call LLM: %v", err)
	}

	done <- true

	var responseContentBuilder strings.Builder
	for _, contentBlock := range llmResponse.Content {
		if textBlock, ok := contentBlock.(*providers.ContentBlockText); ok {
			responseContentBuilder.WriteString(textBlock.Value)
		}
	}

	rawContent := strings.TrimSpace(responseContentBuilder.String())

	if err := saveToFile(params.LLMLogFile, rawContent); err != nil {
		logrus.Error("Failed to save LLM response:", err)
	}

	costEstimate := provider.CostEstimate(llmResponse.ModelId, *llmResponse.Usage)

	logrus.WithFields(logrus.Fields{
		"Total tokens":  llmResponse.Usage.TotalTokens,
		"Input tokens":  llmResponse.Usage.InputTokens,
		"Output tokens": llmResponse.Usage.OutputTokens,
	}).Info("LLM usage:")

	var response gw_model.Config
	if err := yaml.Unmarshal([]byte(rawContent), &response); err != nil {
		return DiscoverQueryResponse{
			Config:       nil,
			Conversation: llmResponse,
			RawContent:   rawContent,
			CostEstimate: costEstimate,
		}, xerrors.Errorf("unable to unmarshal response: %w", err)
	}

	return DiscoverQueryResponse{
		Config:       &response,
		Conversation: llmResponse,
		RawContent:   rawContent,
		CostEstimate: costEstimate,
	}, nil

}
