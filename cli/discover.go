package cli

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/xerrors"

	openai "github.com/sashabaranov/go-openai"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/centralmind/gateway/connectors"
	gw_model "github.com/centralmind/gateway/model"
)

var (
	basePrompt = `
!Important rules:
	- The final output must contain only valid JSON with no additional commentary, explanations, or markdown formatting.
	- The JSON configuration must strictly adhere to the provided JSON schema, including all required fields.
	- Description of API endpoints should have also an example, to help chatbot to use it.
	- All descriptions and summary must not have any sensetive information/data from security point of view including database types, password and etc.
	- All SQL queries must be Pure SQL that will be used in golang SQLx on top of database - {database_type} and be fully parameterized (using named parameters) to prevent SQL injection.
	- All API endpoints must have output schemas.
	- All SQL queries must be verified that they will not return array of data where expected one item.
	- SQL queries should be optimized for {database_type} and use appropirate indexes.
	- Endpoints that return lists must include pagination parameters (offset and limit).
	- Consistent Endpoint Definitions: Each table defined in the DDL should have corresponding endpoints as specified by the JSON schema, including method, path, description, SQL query, and parameters.
	- Sensitive Data Handling: If any columns contain sensitive or PII data like phone number, SSN, address, credit card etc, they must be flagged appropriately (e.g., using a "pii" flag).
	- Each Parameter in API endpoints may have default value taken from corresponded example rows, only if it's not PII or sensitive data
	- If some entity require pagination, there should be separate API that calculate total_count, so pagination can be queried
`
)

var (
	//go:embed api_config_schema.json
	apiConfigSchema []byte
)

type TableData struct {
	Columns []gw_model.ColumnSchema
	Name    string
	Sample  []map[string]any
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

func init() {
	// Configure logrus for nicer output
	logrus.SetFormatter(&logrus.TextFormatter{
		ForceColors:      true,
		FullTimestamp:    false,
		TimestampFormat:  "",
		DisableTimestamp: true,
	})
}

func Discover(configPath *string) *cobra.Command {
	var databaseType string
	var tables []string
	var aiAPIKey string
	var output string
	var extraPrompt string
	cmd := &cobra.Command{
		Use:   "discover",
		Short: "Discover generates gateway config",
		Args:  cobra.MatchAll(cobra.ExactArgs(0)),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			startTime := time.Now()

			// Configure header
			logrus.Info("\r\n")
			logrus.Info("🚀 API Discovery Process")

			logrus.Info("Step 1: Read configs")
			configRaw, err := os.ReadFile(*configPath)
			if err != nil {
				return err
			}
			connector, err := connectors.New(databaseType, configRaw)
			if err != nil {
				return err
			}
			if err := connector.Ping(context.Background()); err != nil {
				return err
			}
			logrus.Info("✅ Step 1 completed. Done.")
			logrus.Info("\r\n")

			logrus.Info("Step 2: Discover data")
			allTables, err := connector.Discovery(context.Background())
			if err != nil {
				return err
			}

			tableSet := map[string]bool{}
			for _, table := range tables {
				tableSet[table] = true
			}
			if len(tables) == 0 {
				for _, table := range allTables {
					tableSet[table.Name] = true
				}
			}

			// Show discovered tables
			logrus.Info("Discovered Tables:")
			for _, table := range allTables {
				if tableSet[table.Name] {
					logrus.Infof("  - %s: %d columns", table.Name, len(table.Columns))
				}
			}

			logrus.Info("✅ Step 2 completed. Done.")
			logrus.Info("\r\n")
			// Sample data
			logrus.Info("Step 3: Sample data from tables")
			var tablesToGenerate []TableData
			for _, table := range allTables {
				if !tableSet[table.Name] {
					continue
				}
				sample, err := connector.Sample(context.Background(), table)
				if err != nil {
					return err
				}
				tablesToGenerate = append(tablesToGenerate, TableData{
					Columns: table.Columns,
					Name:    table.Name,
					Sample:  sample,
				})
			}

			// Show sampled data
			logrus.Info("Data Sampling Results:")
			for _, table := range tablesToGenerate {
				logrus.Infof("  - %s: %d rows sampled", table.Name, len(table.Sample))
			}

			logrus.Info("✅ Step 3 completed. Done.")
			logrus.Info("\r\n")
			// Prepare prompt
			logrus.Info("Step 4: Prepare prompt to AI")
			fullPrompt := generatePrompt(databaseType, extraPrompt, tablesToGenerate)
			promptFilename := "prompt_default.txt"
			if err := saveToFile(promptFilename, fullPrompt); err != nil {
				logrus.Error("failed to save prompt:", err)
			}
			logrus.Infof("Prompt saved locally to %s", promptFilename)

			logrus.Info("✅ Step 4 completed. Done.")
			logrus.Info("\r\n")
			// Call API
			logrus.Info("Step 5: Using AI to design API")
			config, resp, err := callOpenAI(aiAPIKey, fullPrompt)
			if err != nil {
				logrus.Error("failed to call OpenAI:", err)
				return err
			}

			// Show generated API endpoints
			var apiEndpoints int
			logrus.Info("API Functions Created:")
			for _, table := range config.Database.Tables {
				for _, endpoint := range table.Endpoints {
					logrus.Infof("  - %s %s - %s", endpoint.HTTPMethod, endpoint.HTTPPath, endpoint.Summary)
					apiEndpoints++
				}
			}

			config.Database.Type = databaseType
			config.Database.Connection = string(configRaw)

			// Save configuration
			configData, err := yaml.Marshal(config)
			if err != nil {
				logrus.Error("yaml failed:", err)
				return err
			}

			if err := saveToFile(output, string(configData)); err != nil {
				logrus.Error("failed:", err)
				return err
			}

			logrus.Infof("API schema saved to: %s", output)
			logrus.Info("\r\n")
			logrus.Info("✅ Step 5: API Specification Generation Completed!")
			logrus.Info("\r\n")
			// Show statistics
			duration := time.Since(startTime)
			tokensUsed := resp.Usage.TotalTokens

			logrus.Info("✅ All steps completed. Done.")
			logrus.Info("\r\n")
			logrus.Info("--- Execution Statistics ---")
			logrus.Infof("Total time taken: %v", duration.Round(time.Second))
			logrus.Infof("Tokens used: %d (Estimated cost: $%.4f)",
				tokensUsed, (float64(resp.Usage.PromptTokens)/1000000)*1.1+(float64(resp.Usage.CompletionTokens)/1000000)*4.4)
			logrus.Infof("Tables processed: %d", len(tablesToGenerate))
			logrus.Infof("API methods created: %d", apiEndpoints)

			// Count PII columns from the generated config
			var piiColumnsCount int
			for _, table := range config.Database.Tables {
				for _, column := range table.Columns {
					if column.PII {
						piiColumnsCount++
					}
				}
			}
			logrus.Infof("Total number of columns with PII data: %d", piiColumnsCount)

			return nil
		},
	}
	cmd.Flags().StringSliceVar(&tables, "tables", nil, "List of table to include")
	cmd.Flags().StringVar(&databaseType, "db-type", "postgres", "Type of database")
	cmd.Flags().StringVar(&aiAPIKey, "ai-api-key", "ai-api-key", "AI API token")
	cmd.Flags().StringVar(&output, "output", "gateway.yaml", "Resulted yaml path")
	cmd.Flags().StringVar(&extraPrompt, "prompt", "generate reasonable set of API-s for this data", "Custom input to generate API-s")
	return cmd
}

func generatePrompt(databaseType, extraPrompt string, tables []TableData) string {
	res := "I need a config for an automatic API that will be used by another AI bot or LLMs..."
	res += "\n"
	res += strings.ReplaceAll(basePrompt, "{database_type}", databaseType)
	res += "\n" + string(apiConfigSchema) + "\n" + extraPrompt + "\n\n"
	for _, table := range tables {
		res += fmt.Sprintf(`
<%[1]s number_columns=%[5]v number_rows=%[4]v>
schema:
%[2]s
---
data_sample:
%[3]s
</%[1]s>

`, table.Name, yamlify(table.Columns), yamlify(table.Sample), len(table.Sample), len(table.Columns))
	}

	return res
}

func yamlify(sample any) string {
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

func saveToFile(filename, data string) error {
	return os.WriteFile(filename, []byte(data), 0644)
}

// startSpinner starts a loading animation in the console
func startSpinner(message string, done chan bool) {
	spinChars := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	i := 0
	for {
		select {
		case <-done:
			fmt.Printf("\r%s... Done!     \n", message)
			return
		default:
			fmt.Printf("\r%s %s", spinChars[i], message)
			time.Sleep(100 * time.Millisecond)
			i = (i + 1) % len(spinChars)
		}
	}
}

func callOpenAI(apiKey string, prompt string) (*gw_model.Config, openai.ChatCompletionResponse, error) {
	client := openai.NewClient(apiKey)

	// Create a channel to control the spinner
	done := make(chan bool)
	go startSpinner("Thinking. The process can take a few minutes to finish", done)

	resp, err := client.CreateChatCompletion(
		context.TODO(),
		openai.ChatCompletionRequest{
			Model:           "o3-mini",
			Messages:        []openai.ChatCompletionMessage{{Role: "user", Content: prompt}},
			ReasoningEffort: "high",
		},
	)

	// Stop the spinner
	done <- true

	if err != nil {
		return nil, openai.ChatCompletionResponse{}, xerrors.Errorf("fail to call open-ai: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"Total tokens":  resp.Usage.TotalTokens,
		"Input tokens":  resp.Usage.PromptTokens,
		"Output tokens": resp.Usage.CompletionTokens,
	}).Info("OpenAI usage:")

	answerText := strings.TrimSpace(resp.Choices[0].Message.Content)
	if err := saveToFile("open-ai-raw.log", answerText); err != nil {
		return nil, openai.ChatCompletionResponse{}, xerrors.Errorf("unable to save raw response: %w", err)
	}

	var res gw_model.Config
	if err := yaml.Unmarshal([]byte(answerText), &res); err != nil {
		return nil, openai.ChatCompletionResponse{}, xerrors.Errorf("unable to unmarshal response: %w", err)
	}
	return &res, resp, nil
}
