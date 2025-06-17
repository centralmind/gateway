---
title: 'Google Vertex AI (Anthropic)'
description: 'Integration with Anthropic Claude models via Google Vertex AI'
---

The Google Vertex AI (Anthropic) provider enables access to Claude models through Google Cloud's Vertex AI platform. This guide covers setup, configuration, authentication, and usage options specific to the Vertex AI integration.

## Overview

[Google Vertex AI](https://cloud.google.com/vertex-ai) offers access to Anthropic's Claude models through Google Cloud's infrastructure. This provider leverages Google Cloud authentication to securely access Claude models with enterprise-grade security, compliance features, and the benefits of Google Cloud's global infrastructure.

## Google Cloud Authentication

Unlike the direct Anthropic API integration, this provider uses Google Cloud authentication mechanisms:

- **Google Application Default Credentials (ADC)**: The provider uses standard Google authentication that automatically detects credentials from your environment.
- **Project ID**: You must specify a Google Cloud project ID where Vertex AI is enabled.
- **Region**: The Google Cloud region where the models will be accessed (defaults to "us-east1").

For more details on setting up Google Cloud authentication, refer to the following resources:

- [Setting up Application Default Credentials](https://cloud.google.com/docs/authentication/provide-credentials-adc)
- [Google Cloud CLI Installation](https://cloud.google.com/sdk/docs/install)

## Setting Up Authentication

1. Install the Google Cloud CLI:

   ```bash
   # Follow instructions at https://cloud.google.com/sdk/docs/install
   ```

2. Log in and set up default credentials:

   ```bash
   gcloud auth login
   gcloud auth application-default login
   ```

3. Set your default project:
   ```bash
   gcloud config set project YOUR_PROJECT_ID
   ```

## Example Usage

Below is a basic example of how to use the provider with Vertex AI:

```bash
./gateway discover \
  --ai-provider anthropic-vertexai \
  --vertexai-region your-gcp-region \
  --vertexai-project your-gcp-project-id \
  --connection-string "postgresql://my_user:my_pass@localhost:5432/mydb"
```

## Project and Region Configuration

The provider determines which Google Cloud project and region to use in the following order:

1. Command line flags: `--vertexai-project` and `--vertexai-region`
2. Environment variables: `ANTHROPIC_VERTEXAI_PROJECT` and `ANTHROPIC_VERTEXAI_REGION`
3. Default region fallback to `us-east1` (if no region specified)

Example with explicit project and region:

```bash
./gateway discover \
  --ai-provider anthropic-vertexai \
  --vertexai-project your-gcp-project-id \
  --vertexai-region us-central1 \
  --connection-string "postgresql://my_user:my_pass@localhost:5432/mydb"
```

Alternatively, using environment variables:

```bash
export ANTHROPIC_VERTEXAI_PROJECT="your-gcp-project-id"
export ANTHROPIC_VERTEXAI_REGION="us-central1"
./gateway discover \
  --ai-provider anthropic-vertexai \
  --connection-string "postgresql://my_user:my_pass@localhost:5432/mydb"
```

## Model Selection

By default, the Vertex AI provider uses `claude-3-7-sonnet@20250219`. Note the different format from the direct Anthropic API, using `@` instead of `-` for date versions.

You can specify a different model using:

1. **Command-line Flag:** Use the `--ai-model` flag.
2. **Environment Variable:** Set the `ANTHROPIC_MODEL_ID`.

Examples:

```bash
# Specify model via command line
./gateway discover \
  --ai-provider anthropic-vertexai \
  --ai-model claude-3-7-sonnet@20250219 \
  --connection-string "postgresql://my_user:my_pass@localhost:5432/mydb"

# Or via environment variable
export ANTHROPIC_MODEL_ID=claude-3-7-sonnet@20250219
./gateway discover \
  --ai-provider anthropic-vertexai \
  --connection-string "postgresql://my_user:my_pass@localhost:5432/mydb"
```

## Advanced Configuration

### Reasoning Mode

Enable Claude's "thinking" mode for complex reasoning tasks:

```bash
./gateway discover \
  --ai-provider anthropic-vertexai \
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
  --ai-provider anthropic-vertexai \
  --ai-max-tokens 8192 \
  --connection-string "postgresql://my_user:my_pass@localhost:5432/mydb"
```

If not specified, the default maximum token count is 64000 tokens.

### Temperature Adjustment

Adjust the randomness of responses with the temperature parameter:

```bash
./gateway discover \
  --ai-provider anthropic-vertexai \
  --ai-temperature 0.5 \
  --connection-string "postgresql://my_user:my_pass@localhost:5432/mydb"
```

Lower values produce more deterministic outputs, while higher values increase creativity and randomness.

## Usage Costs

The Vertex AI provider includes cost estimation for Claude Sonnet models:

- **Input tokens:** $3.75 per 1 million tokens
- **Output tokens:** $15.00 per 1 million tokens

Costs are calculated based on the actual token usage for each request. Note that actual billing is handled through your Google Cloud account, and pricing may vary based on your specific agreements with Google Cloud.

## Recommended Best Practices

- **Use Service Accounts:** For production deployments, create a dedicated service account with minimal permissions.
- **Configure IAM Permissions:** Ensure your account has the necessary Vertex AI permissions.
- **Manage Token Count:** Set a reasonable maximum token count to control costs.
- **Enable Reasoning Mode:** Use for complex analytical tasks.
- **Regional Selection:** Choose a region close to your users/applications for lower latency.

## Additional Resources

- [Google Cloud Vertex AI Documentation](https://cloud.google.com/vertex-ai/docs)
- [Google Cloud Authentication Overview](https://cloud.google.com/docs/authentication)
- [Service Account Setup Guide](https://cloud.google.com/iam/docs/service-accounts-create)
- [Vertex AI Pricing Information](https://cloud.google.com/vertex-ai/pricing)
- [Claude on Vertex AI Documentation](https://cloud.google.com/vertex-ai/docs/generative-ai/model-reference/claude)
