---
title: 'Generating an API'
---

This guide explains how to generate an API using Gateway's discovery mechanism.

## Prerequisites

Before generating an API, ensure you have:

1. Gateway installed using one of the [installation methods](/docs/content/getting-started/installation)
2. Get connection string to your database and make sure its accessable
3. Prepare LLM provider API key

## Using the Discovery Command

Gateway provides a convenient command for automatically discovering and generating API configurations:

```bash
# Basic command to get help
./gateway --help
```

### Choosing one of our supported AI providers:

- [OpenAI](/providers/openai) and all OpenAI-compatible providers
- [Anthropic](/providers/anthropic)
- [Amazon Bedrock](/providers/bedrock)
- [Google Vertex AI (Anthropic)](/providers/anthropic-vertexai)
- [Google Gemini](https://docs.centralmind.ai/providers/gemini)

[Google Gemini](https://docs.centralmind.ai/providers/gemini) provides a generous **free tier**. You can obtain an API key by visiting Google AI Studio:

- [Google AI Studio](https://aistudio.google.com/apikey)

Once logged in, you can create an API key in the API section of AI Studio. The free tier includes a generous monthly token allocation, making it accessible for development and testing purposes.

Configure AI provider authorization. For Google Gemini, set an API key.

```bash
export GEMINI_API_KEY='yourkey'
```

### Running the Discovery Command with AI Assistance

Use the following command to generate an API with AI assistance:

```bash
./gateway discover \
  --ai-provider gemini \
  --connection-string "postgresql://my_user:my_pass@localhost:5432/mydb" \
  --prompt "Develop an API that enables a chatbot to retrieve information about data. \
Try to place yourself as analyst and think what kind of data you will require, \
based on that come up with useful API methods for that"
```

#### Parameter Descriptions:

- `discover`: Activates the discovery mechanism to analyze your database using AI
- `--ai-provider`: Supported [AI Provider](/providers)
- `--connection-string`: Connection string to the database format: `[database_type]://[user]:[password]@[host][:port][/dbname]`
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
   ./gateway start --config gateway.yaml
   ```
