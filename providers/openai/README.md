---
title: 'OpenAI'
description: 'Integration with OpenAI API for accessing GPT and O models'
---

The OpenAI provider enables direct integration with OpenAI's models including o3-mini. This guide covers setup, configuration, authentication, and usage options for connecting to OpenAI's API.

## Overview

The OpenAI provider allows direct access to [OpenAI's language models](https://platform.openai.com/docs/models), including the latest O series and GPT models. This provider offers a streamlined integration with robust authentication, flexible configuration options, and support for advanced features like high reasoning effort and JSON responses.

## Authentication

The provider uses API key authentication to access OpenAI's services. You'll need to obtain an API key from OpenAI to use this provider:

- **Environment Variable:** Set `OPENAI_API_KEY` to provide your credentials.
- **Command Line:** Pass your API key using the appropriate flag.

For more details on obtaining and managing OpenAI API keys, refer to OpenAI's documentation:

- [OpenAI API Documentation](https://platform.openai.com/docs/api-reference/authentication)

## Example Usage

```bash
export OPENAI_API_KEY='yourkey'
```

Below is a basic example of how to use the provider with a connection configuration file:

```bash
./gateway discover \
  --ai-provider openai \
  --connection-string "postgresql://my_user:my_pass@localhost:5432/mydb"
```

## Endpoint Configuration

By default, the provider connects to OpenAI's standard API endpoint. You can specify a custom endpoint using one of the following methods:

1. **Configuration File:** Include the endpoint in your connection.yaml
2. **Environment Variable:** Set the `OPENAI_ENDPOINT` variable.

Example with a custom endpoint:

```bash
export OPENAI_ENDPOINT="https://custom-openai-endpoint.example.com"
./gateway discover \
  --ai-provider openai \
  --connection-string "postgresql://my_user:my_pass@localhost:5432/mydb"
```

## Model Selection

By default, the OpenAI provider uses `o3-mini`. You can specify a different model using one of the following methods:

1. **Command-line Flag:** Use the `--ai-model` flag.
2. **Environment Variable:** Set the `OPENAI_MODEL_ID`.

Examples:

```bash
# Specify model via command line
./gateway discover \
  --ai-provider openai \
  --ai-model o3-mini \
  --connection-string "postgresql://my_user:my_pass@localhost:5432/mydb"

# Or via environment variable
export OPENAI_MODEL_ID=o3-mini
./gateway discover \
  --ai-provider openai \
  --connection-string "postgresql://my_user:my_pass@localhost:5432/mydb"
```

## Advanced Configuration

### Reasoning Mode

Enable OpenAI's high reasoning effort for complex tasks:

```bash
./gateway discover \
  --ai-provider openai \
  --ai-reasoning=true \
  --connection-string "postgresql://my_user:my_pass@localhost:5432/mydb"
```

When reasoning mode is enabled, the provider sets the `reasoning_effort` parameter to "high".

### Response Length Control

Control the maximum token count in responses:

```bash
./gateway discover \
  --ai-provider openai \
  --ai-max-tokens 8192 \
  --connection-string "postgresql://my_user:my_pass@localhost:5432/mydb"
```

If not specified, the default maximum token count is 100,000 tokens.

### Temperature Adjustment

Adjust the randomness of responses with the temperature parameter:

```bash
./gateway discover \
  --ai-provider openai \
  --ai-temperature 0.7 \
  --connection-string "postgresql://my_user:my_pass@localhost:5432/mydb"
```

Lower values produce more deterministic outputs, while higher values increase creativity and randomness.

## Usage Costs

The OpenAI provider includes cost estimation for various models:

| Model       | Input Cost (per 1M tokens) | Output Cost (per 1M tokens) |
| ----------- | -------------------------- | --------------------------- |
| gpt-4o-mini | $0.15                      | $0.60                       |
| gpt-4o      | $2.50                      | $10.00                      |
| o3-mini     | $1.10                      | $4.40                       |
| o1          | $15.00                     | $60.00                      |

Costs are calculated based on the actual token usage for each request.

## Recommended Best Practices

- **API Key Security:** Use environment variables for sensitive settings like API keys.
- **Manage Token Count:** Set a reasonable maximum token count to control costs.
- **Enable Reasoning Mode:** Use for complex analytical tasks.
- **Select the Right Model:** Choose models based on your specific needs and budget constraints.

## Additional Resources

- [OpenAI API Documentation](https://platform.openai.com/docs/introduction)
- [OpenAI Models Overview](https://platform.openai.com/docs/models)
