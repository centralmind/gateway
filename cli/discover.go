package cli

import (
	"context"
	_ "embed"
	"github.com/centralmind/gateway/connectors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/centralmind/gateway/prompter"
	"github.com/centralmind/gateway/providers"

	"github.com/centralmind/gateway/logger"
	"golang.org/x/xerrors"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	gw_model "github.com/centralmind/gateway/model"
)

var (
	// CLI-colors
	red    string = "\033[31m"
	green         = "\033[32m"
	cyan          = "\033[36m"
	yellow        = "\033[33m"
	violet        = "\033[35m"
	reset         = "\033[0m" // reset color
)

func init() {
	// Configure logrus for nicer output
	logrus.SetFormatter(&logrus.TextFormatter{
		DisableLevelTruncation: true,
		ForceColors:            true,
		FullTimestamp:          false,
		TimestampFormat:        "",
		DisableTimestamp:       true,
	})
}

type dummyConn struct {
	Schema     string `yaml:"schema"`
	ConnString string `yaml:"conn_string"`
}

func Discover() *cobra.Command {
	var tables string
	var aiProvider string
	var aiEndpoint string
	var aiAPIKey string
	var aiModel string
	var aiMaxTokens int
	var aiTemperature float32
	var aiReasoning bool
	var bedrockRegion string
	var vertexAIRegion string
	var vertexAIProject string
	var output string
	var extraPrompt string
	var promptFile string
	var llmLogFile string
	var dbDSN string
	var dbSchema string
	var typ string

	cmd := &cobra.Command{
		Use:   "discover",
		Short: "Discover generates gateway config",
		Long: `Automatically generate a gateway configuration using AI.

This command connects to a database, analyzes its schema, and uses AI to generate
an optimized gateway configuration file. The generated configuration includes
REST API endpoints and MCP protocol definitions tailored for AI agent access.

The discovery process follows these steps:
1. Connect to the database and verify the connection
2. Discover table schemas and sample data
3. Generate an AI prompt based on the discovered schema
4. Use the specified AI provider to generate a gateway configuration
5. Save the generated configuration to a file

This approach significantly reduces the time needed to create gateway configurations
and ensures they follow best practices for AI agent interactions.`,
		Args: cobra.MatchAll(cobra.ExactArgs(0)),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			startTime := time.Now()

			logrus.Info("\r\n")
			logrus.Info("🚀 Verify Discovery Process")

			if typ == "" {
				typ = strings.Split(dbDSN, ":")[0]
			}

			var dbConfig any
			dbConfig = dbDSN
			if dbSchema != "" {
				dbConfig = dummyConn{Schema: dbSchema, ConnString: dbDSN}
			}

			connector, err := connectors.New(typ, dbConfig)
			if err != nil {
				return xerrors.Errorf("Failed to create connector: %w", err)
			}

			resolvedTables, err := TablesData(splitTables(tables), connector)
			if err != nil {
				return xerrors.Errorf("unable to verify connection: %w", err)
			}

			databaseType := connector.Config().Type()

			logrus.Info("Step 4: Prepare the prompt for the AI")
			discoverPrompt := prompter.DiscoverEndpointsPrompt(connector, extraPrompt, resolvedTables, prompter.SchemaFromConfig(connector.Config()))
			if err := saveToFile(promptFile, discoverPrompt); err != nil {
				logrus.Error("failed to save prompt:", err)
			}

			logrus.Infof("Prompt saved locally to %s", promptFile)
			logrus.Info("✅ Step 4 completed. Done.")
			logrus.Info("\r\n")

			// Call API
			logrus.Info("Step 5: Use AI to design the API")
			response, err := makeDiscoverQuery(DiscoverQueryParams{
				LLMLogFile:    llmLogFile,
				Provider:      aiProvider,
				Endpoint:      aiEndpoint,
				APIKey:        aiAPIKey,
				Model:         aiModel,
				MaxTokens:     aiMaxTokens,
				Temperature:   aiTemperature,
				Reasoning:     aiReasoning,
				BedrockRegion: bedrockRegion,
				VertexRegion:  vertexAIRegion,
				VertexProject: vertexAIProject,
			}, discoverPrompt)

			if err != nil {
				logrus.Error("Failed to call the LLM:", err)
				return err
			}

			var config gw_model.Config

			// Show generated API endpoints
			var apiEndpoints int
			logrus.Info("API Functions Created:")
			for _, endpoint := range response.Endpoints {
				logrus.Infof("  - "+cyan+"%s"+reset+" "+violet+"%s"+reset+" - %s", endpoint.HTTPMethod, endpoint.HTTPPath, endpoint.Summary)
				apiEndpoints++
			}

			config.Database.Type = databaseType
			config.Database.Connection = dbDSN
			config.Database.Endpoints = response.Endpoints

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
			logrus.Info("\r\n")
			logrus.Infof("API schema saved to: "+cyan+"%s"+reset, output)

			logrus.Info("✅ Step 5: API Specification Generation Completed!")
			logrus.Info("\r\n")
			// Show statistics
			duration := time.Since(startTime)

			logrus.Info("✅ All steps completed. Done.")
			logrus.Info("\r\n")
			logrus.Info("--- Execution Statistics ---")
			logrus.Infof("Total time taken: "+yellow+"%v"+reset, duration.Round(time.Second))
			logrus.Infof(
				"Tokens used: "+yellow+"%d"+reset+" (Estimated cost: "+violet+"$%.4f"+reset+")",
				response.Conversation.Usage.TotalTokens,
				response.CostEstimate,
			)
			logrus.Infof("Tables processed: "+yellow+"%d"+reset, len(resolvedTables))
			logrus.Infof("API methods created: "+yellow+"%d"+reset, apiEndpoints)

			return nil
		},
	}

	cmd.Flags().StringVarP(&dbDSN, "connection-string", "C", "", "Database connection string (DSN) for direct database connection")
	cmd.Flags().StringVar(&dbSchema, "db-schema", "", "Database schema for database connection, optional")
	cmd.Flags().StringVar(&typ, "type", "", "Type of database to use (for example: postgres os mysql)")
	cmd.Flags().StringVar(&tables, "tables", "", "Comma-separated list of tables to include (e.g., 'users,products,orders')")

	/*
		AI provider options:
	*/
	cmd.Flags().StringVar(&aiProvider, "ai-provider", "openai", "AI provider to use (openai, anthropic, bedrock, vertexai, etc.)")
	cmd.Flags().StringVar(&aiEndpoint, "ai-endpoint", "", "Custom OpenAI-compatible API endpoint URL for self-hosted models")
	cmd.Flags().StringVar(&aiAPIKey, "ai-api-key", "", "API key for the selected AI provider")
	cmd.Flags().StringVar(&bedrockRegion, "bedrock-region", "", "AWS region for Amazon Bedrock (required when using bedrock provider)")
	cmd.Flags().StringVar(&vertexAIRegion, "vertexai-region", "", "Google Cloud region for Vertex AI (required when using vertexai provider)")
	cmd.Flags().StringVar(&vertexAIProject, "vertexai-project", "", "Google Cloud project ID for Vertex AI (required when using vertexai provider)")
	cmd.Flags().StringVar(&aiModel, "ai-model", "", "Specific AI model to use (e.g., 'gpt-4', 'claude-3-opus', etc.)")
	cmd.Flags().IntVar(&aiMaxTokens, "ai-max-tokens", 0, "Maximum tokens to generate in the AI response (0 for model default)")
	cmd.Flags().Float32Var(&aiTemperature, "ai-temperature", -1.0, "AI temperature for response randomness (0.0-1.0, lower is more deterministic)")
	cmd.Flags().BoolVar(&aiReasoning, "ai-reasoning", true, "Enable AI reasoning in the response for better explanation of design decisions")

	cmd.Flags().StringVar(&output, "output", "gateway.yaml", "Path to save the generated gateway configuration file")
	cmd.Flags().StringVar(&extraPrompt, "prompt", "generate reasonable set of APIs for this data", "Custom instructions for the AI to guide API generation")
	cmd.Flags().StringVar(&promptFile, "prompt-file", filepath.Join(logger.DefaultLogDir(), "prompt_default.txt"), "Path to save the generated AI prompt for inspection")
	cmd.Flags().StringVar(&llmLogFile, "llm-log", filepath.Join(logger.DefaultLogDir(), "llm_raw_response.log"), "Path to save the raw AI response for debugging")

	return cmd
}

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
	Endpoints    []gw_model.Endpoint `yaml:"endpoints"`
	Conversation *providers.ConversationResponse
	RawContent   string
	CostEstimate float64
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
		logrus.Fatalf("Failed to initialize provider: %v", err)
	}

	logrus.Infof("Calling provider: %s", provider.GetName())

	done := make(chan bool)
	go startSpinner("Thinking. The process can take a few minutes to finish", done)

	request := &providers.ConversationRequest{
		ModelId:      params.Model,
		Reasoning:    params.Reasoning,
		MaxTokens:    params.MaxTokens,
		Temperature:  params.Temperature,
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

	if err := os.WriteFile(params.LLMLogFile, []byte(rawContent), 0644); err != nil {
		logrus.Error("Failed to save LLM response:", err)
	}

	costEstimate := provider.CostEstimate(llmResponse.ModelId, *llmResponse.Usage)

	logrus.WithFields(logrus.Fields{
		"Total tokens":  llmResponse.Usage.TotalTokens,
		"Input tokens":  llmResponse.Usage.InputTokens,
		"Output tokens": llmResponse.Usage.OutputTokens,
	}).Info("LLM usage:")

	var response DiscoverQueryResponse
	if err := yaml.Unmarshal([]byte(rawContent), &response); err != nil {
		return DiscoverQueryResponse{
			Endpoints:    nil,
			Conversation: llmResponse,
			RawContent:   rawContent,
			CostEstimate: costEstimate,
		}, xerrors.Errorf("unable to unmarshal response: %w", err)
	}

	return DiscoverQueryResponse{
		Endpoints:    response.Endpoints,
		Conversation: llmResponse,
		RawContent:   rawContent,
		CostEstimate: costEstimate,
	}, nil

}
