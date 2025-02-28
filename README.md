---
title: 'CentralMind'
description: 'Build a data platform for LLMs in one day. Securely connect any data source and let AI handle the rest.'
---

<h1 align="center">CentralMind Gateway: AI-First Data Gateway</h1>

<div align="center">

## 🛸 Introduction

</div>

AI agents and LLM-powered applications need fast, secure access to data, but traditional APIs and databases aren’t built for this. We’re building an API layer that automatically generates secure, LLM-optimized APIs on top of your structured data.

- Filters out PII and sensitive data to ensure compliance with GDPR, CPRA, SOC 2, and other regulations.
- Adds traceability and auditing, so AI applications aren’t black boxes and security teams can control.
- Optimizes for AI workloads, supports Model Context Protocol (MCP) with extra meta information to help AI agents understand APIs, caching and security.

Our first users are companies deploying AI agents for customer support and analytics, where they need models to access the right data without security risks or compliance headaches.

![demo](/assets/demo.gif)


## Features
- ⚡ **Automatic API Generation** – Creates APIs using LLM based on table schema and sampled data.
- 🗄️ **Structured Database Support** – Works with PostgreSQL, MySQL, ClickHouse, and Snowflake.
- 🌍 **Run APIs as Rest or MCP Server** – Easily expose APIs in multiple protocols.
- 📜 **Swagger & OpenAPI 3.1.0 Documentation** – Automatically generated API documentation and OpenAPI spec.
- 🔒 **Automatic PII Cleanup** – Uses regex rules, (Microsoft Presidio coming soon).
- ⚡ **Configurable via YAML & Plugin System** – Extend API functionality effortlessly.
- 🐳 **Run as Binary or Docker** – Comes with a ready-to-use Helm chart.
- 🔑 **Row-Level Security (RLS)** – Restrict data access using Lua scripts.
- 🔐 **Authentication** – Supports API keys and OAuth.
- 👀 **Observability & Audit Trail** – Uses OpenTelemetry (OTel) for tracking requests.
- 🏎️ **Caching** – Supports time-based and LRU caching for efficiency.

## How it Works

<div align="center">

![img.png](assets/diagram.png)

</div>

### Connect & Discover  
Gateway connects to your structured databases like PostgreSQL. Automatically analyzes the schema and samples data to generate an optimized API structure based on your prompt. Ensures security by detecting PII

### Deploy  
Runs as a standalone binary, Docker container, or Helm chart for Kubernetes. Configuration is managed via YAML and a plugin system, allowing customization without modifying the core code. Supports row-level security (RLS) with Lua scripts, caching strategies like LRU and time-based expiration, and observability through OpenTelemetry. Cleaning PII data using regex rules.   

### Use & Integrate  
Exposes APIs through REST, and MCP with built-in authentication via API keys and OAuth. Designed for seamless integration with AI models, including OpenAI, Anthropic Claude, Google Gemini, and DeepSeek. Automatically provides OpenAPI 3.1.0 documentation for easy adoption and supports flexible query execution with structured access control.  


## How to generate

Gateway is LLM-model first, i.e. it's designed to be generated via LLM-models.
To generate your gateway config simply run discover command with your connection info:

1. Connection info
   ```yaml
   hosts:
   - localhost
   user: postgres
   password: password
   database: mydb
   port: 5432
   ```
2. Discovery command
   ```shell
   gateway start  \
      --config PATH_TO_CONFIG \
      discover \
      --db-type postgres \
      --tables table_name_1 --tables table_name_2 \ 
      --ai-api-key $TOKEN \
      --prompt "Generate for me awesome readonly api"
   ```
3. Wait for completion
   ```shell
      INFO 🚀 API Discovery Process
      INFO Step 1: Read configs
      INFO ✅ Step 1 completed. Done.

      INFO Step 2: Discover data
      INFO Discovered Tables:
      INFO   - payment_dim: 3 columns
      INFO   - fact_table: 9 columns
      ...
      INFO ✅ Step 2 completed. Done.

      INFO Step 3: Sample data from tables
      INFO Data Sampling Results:
      INFO   - payment_dim: 5 rows sampled
      INFO   - fact_table: 5 rows sampled
      ...
      INFO ✅ Step 3 completed. Done.

      INFO Step 4: Prepare prompt to AI
      INFO Prompt saved locally to prompt_default.txt
      INFO ✅ Step 4 completed. Done.

      INFO Step 5: Using AI to design API
      Waiting for OpenAI response... Done!     
      INFO OpenAI usage:  Input tokens=3187 Output tokens=14872 Total tokens=18059
      INFO API Functions Created:
      INFO   - GET /payment_dim/{payment_key} - Retrieve a payment detail by its payment key
      INFO   - GET /payment_dim - List payment records with pagination
      INFO   - GET /payment_dim/count - Retrieve total count of payment records
      INFO   - GET /fact_table/{payment_key} - Retrieve a transaction detail by its payment key
      INFO   - GET /fact_table - List transaction records with pagination
      .....
      INFO API schema saved to: gateway.yaml

      INFO ✅ Step 5: API Specification Generation Completed!

      INFO ✅ All steps completed. Done.

      INFO --- Execution Statistics ---
      INFO Total time taken: 2m12s
      INFO Tokens used: 18059 (Estimated cost: $0.0689)
      INFO Tables processed: 6
      INFO API methods created: 18
      INFO Total number of columns with PII data: 2
   ```
4. Explore results, the result would be saved in output file:
   ```yaml
   api:
       name: Awesome Readonly API
       description: ""
       version: "1.0"
   database:
       type: YOUR_DB_TYPE
       connection: YOUR_CONNECTION_INFO
       tables:
           - name: table_name_1
             columns:
               ... // Columns for this table
             endpoints:
               - http_method: GET
                 http_path: /some_path
                 mcp_method: some_method
                 summary: Some readable summary.
                 description: 'Some description'
                 query: SQL Query with params
                 params:
                   ... // List of params for query
   ```


## How to run

```shell
go build .
./gateway start --config ./example/gateway.yaml rest
```

### Docker compose

```shell
docker compose up ./example/docker-compose.yml
```

### MCP Protocol

Gateway implement MCP protocol, for easy access to your data right from claude, to use it

1. Build binary
    ```shell
    go build .
    ```
2. Add gateway to claude integrations config:
   ```json
   {
    "mcpServers": {
        "gateway": {
            "command": "PATH_TO_GATEWAY_BINARY",
            "args": [
                "start", 
                "--config",
                "PATH_TO_GATEWAY_YAML_CONFIG", 
                "mcp-stdio"
            ]
        }
    }
   }
   ```
3. Ask something regards your data:
   ![claude_integration.png](./assets/claude_integration.png)

## Roadmap
- 🗄️ **Expand Database Support** – Add support for Redshift, S3, Oracle, MS SQL, Elasticsearch.
- 🔐 **MCP with Authentication** – Secure Model Context Protocol with API keys and OAuth.
- 🤖 **More LLM Providers** – Integrate Anthropic Claude, Google Gemini, DeepSeek.
- 🏠 **Local & On-Prem Deployment** – Allow usage with self-hosted LLMs.
- 📦 **Schema Evolution & Versioning** – Track changes and auto-migrate APIs.
- 🚦 **Traffic Control & Rate Limiting** – Intelligent throttling for high-scale environments.
