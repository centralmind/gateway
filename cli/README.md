---
title: 'Gateway CLI'
---

This document provides information about the available CLI commands and their parameters for the Gateway application.

## Available Commands

### `gateway connectors`

List all available database connectors

**Description:**

Display a list of all registered database connectors with their configuration documentation.

When run without arguments, this command lists all available database connectors.
When run with a specific connector name as an argument, it displays detailed
configuration documentation for that connector.

Examples:
  gateway connectors         # List all available connectors
  gateway connectors postgres # Show documentation for PostgreSQL connector
  gateway connectors mysql    # Show documentation for MySQL connector

**Usage:**

```
gateway connectors [connector-name]
```



  gateway connectors
  gateway connectors postgres
  gateway connectors mysql


### `gateway discover`

Discover generates gateway config

**Description:**

Automatically generate a gateway configuration using AI.

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
and ensures they follow best practices for AI agent interactions.

**Usage:**

```
gateway discover [flags]
```

**Flags:**

- `--ai-api-key` - API key for the selected AI provider
- `--ai-endpoint` - Custom OpenAI-compatible API endpoint URL for self-hosted models
- `--ai-max-tokens` - Maximum tokens to generate in the AI response (0 for model default) (default: "0")
- `--ai-model` - Specific AI model to use (e.g., 'gpt-4', 'claude-3-opus', etc.)
- `--ai-provider` - AI provider to use (openai, anthropic, bedrock, vertexai, etc.) (default: "openai")
- `--ai-reasoning` - Enable AI reasoning in the response for better explanation of design decisions (default: "true")
- `--ai-temperature` - AI temperature for response randomness (0.0-1.0, lower is more deterministic) (default: "-1")
- `--bedrock-region` - AWS region for Amazon Bedrock (required when using bedrock provider)
- `--connection-string` - Database connection string (DSN) for direct database connection
- `--llm-log` - Path to save the raw AI response for debugging (default: "/Users/tserakhau/go/src/github.com/gateway/binaries/.gateway/llm_raw_response.log")
- `--output` - Path to save the generated gateway configuration file (default: "gateway.yaml")
- `--prompt` - Custom instructions for the AI to guide API generation (default: "generate reasonable set of APIs for this data")
- `--prompt-file` - Path to save the generated AI prompt for inspection (default: "/Users/tserakhau/go/src/github.com/gateway/binaries/.gateway/prompt_default.txt")
- `--tables` - Comma-separated list of tables to include (e.g., 'users,products,orders')
- `--type` - Type of database to use (for example: postgres os mysql)
- `--vertexai-project` - Google Cloud project ID for Vertex AI (required when using vertexai provider)
- `--vertexai-region` - Google Cloud region for Vertex AI (required when using vertexai provider)




### `gateway generate-docs`

Generate CLI documentation

**Description:**

Generate CLI documentation in Markdown format based on command definitions

**Usage:**

```
gateway generate-docs [flags]
```

**Flags:**

- `--output` - Path to output README.md file (default: "cli/README.md")




### `gateway plugins`

List all available plugins

**Description:**

Display a list of all registered gateway plugins with their configuration documentation.

Plugins extend the functionality of the gateway by adding custom features,
protocols, or integrations. They can be configured in the gateway.yaml file.

When run without arguments, this command lists all available plugins.
When run with a specific plugin name as an argument, it displays detailed
configuration documentation for that plugin.

**Usage:**

```
gateway plugins [plugin-name]
```



  gateway plugins         # List all available plugins
  gateway plugins auth     # Show documentation for the auth plugin
  gateway plugins cache    # Show documentation for the cache plugin


### `gateway start`

Start gateway

**Description:**

Start the Gateway server that provides both REST API and MCP SSE endpoints optimized for AI agents.

The server launches two main components:
1. REST API server with OpenAPI/Swagger documentation
2. MCP (Message Communication Protocol) SSE server for real-time event streaming

Upon successful startup, the terminal will display URLs for both services.

**Usage:**

```
gateway start [flags]
```

**Flags:**

- `--connection-string` - Database connection string (DSN) for direct database connection
- `--disable-swagger` - Disable Swagger UI documentation (default: "false")
- `--mcp` - Start MCP SSE server (default: "true")
- `--prefix` - URL prefix for all API endpoints
- `--raw` - Enable raw protocol mode optimized for AI agents (default: "true")
- `--rest-api` - Start Rest API server (default: "true")
- `--type` - Type of database to use (for example: postgres os mysql)




### `gateway start stdio`

MCP gateway via std-io

**Usage:**

```
gateway start stdio [flags]
```

**Flags:**

- `--log-file` - Path to log file for MCP gateway operations (default: "/Users/tserakhau/go/src/github.com/gateway/binaries/.gateway/mcp.log")
- `--raw` - Enable raw protocol mode optimized for AI agents (default: "false")




### `gateway verify`

Verify connection config

**Description:**

Verify database connection configuration and inspect table schemas.

This command validates the connection to the database specified in the configuration file,
retrieves schema information for the specified tables, and displays sample data.
It's useful for testing database connectivity and exploring table structures
before configuring the gateway for AI agent access.

The command performs the following steps:
1. Read and validate the connection configuration
2. Connect to the database and discover table schemas
3. Display schema information and sample data for each table
4. Save the discovered information to a YAML file for reference

**Usage:**

```
gateway verify [flags]
```

**Flags:**

- `--connection-string` - Database connection string (DSN) for direct database connection
- `--llm-log` - Path to save the discovered table schemas and sample data (default: "/Users/tserakhau/go/src/github.com/gateway/binaries/.gateway/sample.yaml")
- `--tables` - Comma-separated list of tables to include (e.g., 'users,products,orders')
- `--type` - Type of database to use (for example: postgres os mysql)






## Configuration File

The gateway.yaml configuration file defines:

- API endpoints
- Database connections
- Security settings
- Plugin configurations

Example configuration:

```yaml
# Example gateway.yaml
api:
  # API configuration
database:
  # Database connection settings
plugins:
  # Plugin configurations
```

For detailed configuration options, please refer to the main documentation.
