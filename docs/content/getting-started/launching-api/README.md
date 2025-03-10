---
title: 'Launching an API'
---


This guide explains how to launch the API you created using the Gateway discovery process.

## Prerequisites

Before launching your API, ensure you have:

1. Gateway installed using one of the [installation methods](/docs/content/getting-started/installation)
2. A generated `gateway.yaml` configuration file from the [API generation process](/docs/content/getting-started/generating-api)

## Starting the REST API Server

Once you have your configuration file, you can start the API server with a simple command:

```bash
# Launch the API using your gateway.yaml configuration
./gateway start --config gateway.yaml rest
```

### Parameter Descriptions:

- `start`: Initiates the Gateway service
- `--config gateway.yaml`: Path to your generated API configuration file
- `rest`: Specifies that you want to start a REST API server

### Accessing Your API

After running the command, Gateway will launch a web server with the following default settings:

- **Server Address**: http://localhost:9090
- **Swagger Documentation**: http://localhost:9090/swagger/

The Swagger documentation provides a complete interactive reference for all endpoints in your API, allowing you to:

- Explore available endpoints
- Test API calls directly from the browser
- View request and response schemas
- Understand parameter requirements

### Customizing Server Settings

If you need to customize the server address or port, you can modify the `gateway.yaml` file or provide command-line overrides:

```bash
# Launch on a different port
./gateway start --config gateway.yaml rest --addr :7000
```

#### Managing Secrets with Environment Variables

Gateway supports the use of environment variables in the configuration file through `${VARIABLE_NAME}` syntax. This is particularly useful for managing sensitive information like API keys, database credentials, and other secrets.

##### Using Environment Variables in Configuration

You can use environment variables in your `gateway.yaml` file like this:

```yaml
database:
  connection:
    host: ${DB_HOST}
    user: ${DB_USER}
    password: ${DB_PASSWORD}
    database: ${DB_NAME}

api:
  auth:
    secret_key: ${API_SECRET_KEY}
```

When launching the Gateway, ensure these environment variables are set:

```bash
# Set environment variables
export DB_HOST=localhost
export DB_USER=myuser
export DB_PASSWORD=mysecret
export DB_NAME=mydb
export API_SECRET_KEY=your-secret-key

# Launch the API
./gateway start --config gateway.yaml rest
```

#### Best Practices for Secrets Management

1. Never commit sensitive values directly in configuration files
2. Use environment variables for all sensitive information
3. Consider using secret management tools in production environments
4. Keep development and production secrets separate

## Launching MCP SSE Server Mode

To start Gateway in MCP (Message Communication Protocol) SSE server mode, use the following command:

```bash
# Launch the API in MCP server mode
./gateway start --config gateway.yaml mcp
```

By default it will be available on address:

```
http://localhost:9090/sse  
```

### MCP Server Parameters:

- `start`: Initiates the Gateway service
- `--addr`: Address for gateway server (default: “:9090”)
- `--config gateway.yaml`: Path to your generated API configuration file
- `mcp`: Specifies that you want to start an MCP server

The MCP server mode allows for efficient message-based communication between services.

## Using MCP StdInOut Mode

For scenarios where you need direct input/output communication, you can use the MCP StdInOut mode for example when working with local applications like Claude Desktop or Cursor:

```bash
# Launch the API in MCP StdInOut mode
./gateway start --config gateway.yaml mcp-stdio
```

### MCP StdInOut Parameters:

- `start`: Initiates the Gateway service
- `--config gateway.yaml`: Path to your generated API configuration file
- `mcp-stdio`: Specifies that you want to use MCP with standard input/output

This mode is particularly useful for:
- Testing and debugging MCP communication
- Integration with systems that require direct stdin/stdout communication and local launching applications
- Script-based automation and pipeline processing
