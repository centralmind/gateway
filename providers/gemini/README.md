---
title: 'Google Gemini'
description: 'Integration with Gemini API for accessing Google language models'
---

The Gemini provider enables direct integration with Google's language models through a compatible OpenAI-style API. This guide covers setup, configuration, authentication, and usage options for connecting to the Gemini API.

## Overview

The Gemini provider allows access to Google's language models via an OpenAI-compatible interface. This provider offers streamlined integration with authentication through API keys, flexible configuration options, and support for advanced features.

## Authentication

The provider uses API key authentication to access Gemini's services. You'll need to obtain a Gemini API key to use this provider:

- **Environment Variable:** Set `GEMINI_API_KEY` to provide your credentials.
- **Command Line:** Pass your API key using the appropriate flag.

### Getting an API Key

Google offers a **free tier** for Gemini API access. You can obtain an API key by visiting Google AI Studio:

- [Google AI Studio](https://aistudio.google.com/apikey)

Once logged in, you can create an API key in the API section of AI Studio. The free tier includes a generous monthly token allocation, making it accessible for development and testing purposes.

## Example Usage

```bash
export GEMINI_API_KEY='yourkey'
```

Below is a basic example of how to use the provider with a connection configuration file:

```bash
./gateway discover \
  --ai-provider gemini \
  ---connection-string "postgresql://my_user:my_pass@localhost:5432/mydb"
```

## Model Selection

By default, the Gemini provider uses `gemini-2.0-flash-thinking-exp`. You can specify a different model using one of the following methods:

1. **Command-line Flag:** Use the `--ai-model` flag.
2. **Environment Variable:** Set the `GEMINI_MODEL_ID`.

Examples:

```bash
# Specify model via command line
./gateway discover \
  --ai-provider gemini \
  --ai-model gemini-2.0-flash-thinking-exp \
  --connection-string "postgresql://my_user:my_pass@localhost:5432/mydb"

# Or via environment variable
export GEMINI_MODEL_ID=gemini-2.0-flash-thinking-exp
./gateway discover \
  --ai-provider gemini \
  --connection-string "postgresql://my_user:my_pass@localhost:5432/mydb"
```

## Advanced Configuration

### Response Length Control

Control the maximum token count in responses:

```bash
./gateway discover \
  --ai-provider gemini \
  --ai-max-tokens 8192 \
  --connection-string "postgresql://my_user:my_pass@localhost:5432/mydb"
```

If not specified, the default maximum token count is 100,000 tokens.

### Temperature Adjustment

Adjust the randomness of responses with the temperature parameter:

```bash
./gateway discover \
  --ai-provider gemini \
  --ai-temperature 0.7 \
  --connection-string "postgresql://my_user:my_pass@localhost:5432/mydb"
```

Lower values produce more deterministic outputs, while higher values increase creativity and randomness.

## Usage Costs

Google offers a free tier for Gemini API usage with monthly token limits. For production workloads or higher usage requirements, please refer to Google's documentation for the current pricing for Gemini models.

## Recommended Best Practices

- **API Key Security:** Use environment variables for sensitive settings like API keys.
- **Manage Token Count:** Set a reasonable maximum token count to control costs.
- **Select the Right Model:** Choose models based on your specific needs and budget constraints.
- **Start with Free Tier:** Use the free tier to experiment and prototype before committing to paid usage.

## Additional Resources

For more information about Google's language models and their capabilities, please refer to Google's official documentation and AI Studio resources.
