---
title: 'Anthropic'
description: 'Direct integration with Anthropic API for accessing Claude models'
---

The Anthropic API provider enables direct integration with Claude 3.7 Sonnet and other Anthropic models. This guide covers setup, configuration, authentication, and usage options for connecting to Anthropic's API.

## Overview

The Anthropic API provider allows direct access to [Anthropic's Claude models](https://www.anthropic.com/claude), including Claude 3.7 Sonnet. This provider offers a streamlined integration with robust authentication, flexible configuration options, and support for advanced features like thinking mode.

## Authentication

The provider uses API key authentication to access Anthropic's services. You'll need to obtain an API key from Anthropic to use this provider:

- **Environment Variable:** Set `ANTHROPIC_API_KEY` to provide your credentials.
- **Command Line:** Pass your API key using the appropriate flag.

For more details on obtaining and managing Anthropic API keys, refer to Anthropic's documentation:

- [Anthropic API Documentation](https://docs.anthropic.com/)

## Example Usage

```bash
export ANTHROPIC_API_KEY='yourkey'
```

Below is a basic example of how to use the provider with a connection configuration file:

```bash
./gateway discover \
  --ai-provider anthropic \
  --connection-string "postgresql://my_user:my_pass@localhost:5432/mydb"
```

## Endpoint Configuration

By default, the provider connects to Anthropic's standard API endpoint. You can specify a custom endpoint using one of the following methods:

1. **Configuration File:** Include the endpoint in your connection.yaml
2. **Environment Variable:** Set the `ANTHROPIC_ENDPOINT` variable.

Example with a custom endpoint:

```bash
export ANTHROPIC_ENDPOINT="https://custom-anthropic-endpoint.example.com"
./gateway discover \
  --ai-provider anthropic \
  --connection-string "postgresql://my_user:my_pass@localhost:5432/mydb"
```

## Model Selection

By default, the Anthropic provider uses `claude-3-7-sonnet-20250219`. You can specify a different model using one of the following methods:

1. **Command-line Flag:** Use the `--ai-model` flag.
2. **Environment Variable:** Set the `ANTHROPIC_MODEL_ID`.

Examples:

```bash
# Specify model via command line
./gateway discover \
  --ai-provider anthropic \
  --ai-model claude-3-7-sonnet-20250219 \
  --connection-string "postgresql://my_user:my_pass@localhost:5432/mydb"

# Or via environment variable
export ANTHROPIC_MODEL_ID=claude-3-7-sonnet-20250219
./gateway discover \
  --ai-provider anthropic \
  --connection-string "postgresql://my_user:my_pass@localhost:5432/mydb"
```

## Advanced Configuration

### Reasoning Mode

Enable Claude's "thinking" mode for complex reasoning tasks:

```bash
./gateway discover \
  --ai-provider anthropic \
  --ai-reasoning=true \
  --connection-string "postgresql://my_user:my_pass@localhost:5432/mydb"
```

When reasoning mode is enabled, the provider:

- Activates Claude's thinking capability
- Allocates a thinking token budget of 4096 tokens
- Sets the temperature to 1.0

### Response Length Control

Control the maximum token count in responses:

```bash
./gateway discover \
  --ai-provider anthropic \
  --ai-max-tokens 8192 \
  --connection-string "postgresql://my_user:my_pass@localhost:5432/mydb"
```

If not specified, the default maximum token count is 64000 tokens.

### Temperature Adjustment

Adjust the randomness of responses with the temperature parameter:

```bash
./gateway discover \
  --ai-provider anthropic \
  --ai-temperature 0.5 \
  --connection-string "postgresql://my_user:my_pass@localhost:5432/mydb"
```

Lower values produce more deterministic outputs, while higher values increase creativity and randomness.

## Usage Costs

The Anthropic provider includes cost estimation for Claude Sonnet models:

- **Input tokens:** $3.75 per 1 million tokens
- **Output tokens:** $15.00 per 1 million tokens

Costs are calculated based on the actual token usage for each request.

## Recommended Best Practices

- **API Key Security:** Use environment variables for sensitive settings like API keys.
- **Manage Token Count:** Set a reasonable maximum token count to control costs.
- **Enable Reasoning Mode:** Use for complex analytical tasks.

## Additional Resources

- [Anthropic API Documentation](https://docs.anthropic.com/)
