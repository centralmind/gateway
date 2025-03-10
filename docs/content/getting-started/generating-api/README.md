---
title: 'Generating an API'
---

This guide explains how to generate an API using Gateway's discovery mechanism.

## Prerequisites

Before generating an API, ensure you have:

1. Gateway installed using one of the [installation methods](/docs/content/getting-started/installation)
2. Get connection string to your database and make sure its accessable
3. Get OpenAPI key

## Using the Discovery Command

Gateway provides a convenient command for automatically discovering and generating API configurations:

```bash
# Basic command to get help
./gateway --help
```

### Setting up Database Connection

First, create a connection configuration file (e.g., `connection.yaml`) with your database credentials:

```yaml
# Example connection.yaml
type: postgres
hosts:
  - localhost
user: postgres
password: mysecretpassword
database: sampledb
port: 5432
```

### Choosing one of our supported AI providers:

- [OpenAI](/providers/openai) and all OpenAI-compatible providers
- [Anthropic](/providers/anthropic)
- [Amazon Bedrock](/providers/bedrock)
- [Google Vertex AI (Anthropic)](/providers/anthropic-vertexai)

Configure AI provider authorization. For OpenAI, set an API key.

```bash
export OPENAI_API_KEY='yourkey'
```

### Running the Discovery Command with AI Assistance

Use the following command to generate an API with AI assistance:

```bash
./gateway \
  discover \
  --ai-provider openai \
  --config connection.yaml \
  --tables "table_name_1,table_name_2" \
  --prompt "Develop an API that enables a chatbot to retrieve information about data. \
Try to place yourself as analyst and think what kind of data you will require, \
based on that come up with useful API methods for that"
```

#### Parameter Descriptions:

- `discover`: Activates the discovery mechanism to analyze your database using AI
- `--ai-provider`: Supported [AI Provider](/providers)
- `--config connection.yaml`: Path to the database connection configuration file
- `--tables`: Specify which tables to include in API generation (can accept comma-separated list, eg "orders,sales,customers")
- `--prompt "..."`: Customizes the AI's approach to generating the API based on your specific needs

After running this command, Gateway will generate a `gateway.yaml` configuration file. This file contains the complete API definition, including:

- Endpoint definitions
- SQL queries for each endpoint
- Parameter mappings
- Response transformations

You can review and modify this file to verify SQL queries or enable additional features such as PII data cleansing through plugin configurations.

## Next Steps

After generating your API:

1. Review the generated configuration files
2. Customize endpoints and parameters as needed
3. Run Gateway with your configuration:
   ```bash
   ./gateway start --config gateway.yaml rest
   ```
