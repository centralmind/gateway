This connector allows you to automatically generate an secured API layer over your Supabase database tables using CentralMind Gateway. API methods will be automatically created based on your tables and prompt using LLM (OpenAI model).

## Prerequisites

1. Install Gateway binary following the [installation guide](https://docs.centralmind.ai/getting-started/installation)
2. Set up a Supabase project with configured database tables
3. Prepare OpenAI API key or compatible OpenAI API endpoint

## Configuration

You can find credentials on your project's home page if you will click `connect` button in the menu on top. Pick `Transaction pooler` connection string cause its have ipv4 on free tier or any other that is more suitable for your case.

![img](../assets/supabase-connection.jpg)


Create `connection.yaml` with your Supabase database credentials. 
```bash
echo "
type: postgres
hosts:
  - xxx.pooler.supabase.com
user: \"postgres.xxxxx\"
password: \"password\"
database: \"postgres\"
port: 6543" > connection.yaml
```

## Discovery

1.Run the discovery process to analyze your database structure, it will take a few minutes to finish:

```bash
./gateway discover --connection connection.yaml
```

2.Verify the generated configuration in `gateway.yaml`. You can:
   - Review the API structure and SQL Queries
   - Limit tables using `--tables` parameter
   - Add plugins if needed (e.g., PII data cleaning)
   - Configure additional settings

## Run API Server

Start the REST API server:

```bash
./gateway start --config gateway.yaml rest
```



[Optional] Start the MCP SSE API server:

```bash
./gateway start --config gateway.yaml mcp
```

[Optional] Start the MCP stdio API server:

```bash
./gateway start --config gateway.yaml mcp-stdio
```

## Validate that API is working
By default the Swagger UI for API will available locally on:

```
http://localhost:9090/swagger/
```

You should see Swagger UI with ability to execute methods
![img](../assets/supabase-swagger.jpg)

## Available Plugins

You can enhance your API with various plugins:
- <a href="../../plugins/pii_remover/"> PII Data reduction using Regex </a>
- <a href="../../plugins/presidio_anonymizer/"> PII Data reduction using Microsoft Presidio</a>
- <a href="../../plugins/oauth/"> OAuth Authentication</a>
- <a href="../../plugins/api_keys/"> API Keys Management</a>
- <a href="../../plugins/lru_cache/"> LRU Cache</a>
- <a href="../../plugins/otel/"> OpenTelemetry Integration</a>
- And more...


## Additional Configuration

To modify the generated API:
- Edit the `gateway.yaml` configuration
- Add custom plugins if needed
- Modify the discovery process configuration via custom prompt and restart discovery process
- Restart the server to apply changes
