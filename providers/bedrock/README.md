---
title: 'Amazon Bedrock'
description: 'Integration with Amazon Bedrock for accessing Claude and other AI models'
---

The Amazon Bedrock provider enables integration with Claude 3.7 Sonnet and other Anthropic models hosted on AWS Bedrock. This guide covers setup, configuration, authentication, and usage options.

## Overview

[Amazon Bedrock](https://aws.amazon.com/bedrock/) is a fully managed service that offers a selection of high-performing foundation models (FMs), including Anthropic's Claude models. The provider leverages AWS services to securely access these models with robust authentication and flexible configuration options.

## AWS Authorization and Authentication

The provider uses standard AWS authentication mechanisms to manage access to Bedrock services. To ensure secure and seamless integration, make sure you have the necessary IAM permissions. AWS supports multiple methods for credential management, including:

- **Environment Variables:** Set `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` to provide your credentials.
- **AWS Credentials File:** Configure your credentials in the `~/.aws/credentials` file.
- **EC2 Instance Profiles:** For applications running on EC2, IAM roles can provide temporary credentials.

For more details on configuring AWS credentials and best practices, refer to the following resources:

- [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [AWS CLI Configuration Guide](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html)

## CLI Installation

The AWS CLI is a crucial tool for managing your AWS credentials and interacting with AWS services. If you haven't installed it yet, follow the instructions in the official guide:

- [AWS CLI Installation Guide](https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html)

After installation, configure your credentials using:

```bash
aws configure
```

## Example Usage

Below is a basic example of how to use the provider with a connection configuration file:

```bash
./gateway discover \
  --ai-provider bedrock \
  --connection-string "postgresql://my_user:my_pass@localhost:5432/mydb"
```

## Region Configuration

The provider determines which AWS region to use in the following order:

1. Explicitly configured region via the `--bedrock-region` flag
2. Environment variable `BEDROCK_REGION`
3. Environment variable `AWS_REGION`
4. Default fallback to `us-east-1`

Example with an explicit region:

```bash
./gateway discover \
  --ai-provider bedrock \
  --bedrock-region us-west-2 \
  --connection-string "postgresql://my_user:my_pass@localhost:5432/mydb"
```

## Model Selection

By default, the Bedrock provider uses `us.anthropic.claude-3-7-sonnet-20250219-v1:0`. You can specify a different model using one of the following methods:

1. **Command-line Flag:** Use the `--ai-model` flag.
2. **Environment Variable:** Set the `BEDROCK_MODEL_ID`.

Examples:

```bash
# Specify model via command line
./gateway discover \
  --ai-provider bedrock \
  --ai-model us.anthropic.claude-3-7-sonnet-20250219-v1:0 \
  --connection-string "postgresql://my_user:my_pass@localhost:5432/mydb"

# Or via environment variable
export BEDROCK_MODEL_ID=us.anthropic.claude-3-7-sonnet-20250219-v1:0
./gateway discover \
  --ai-provider bedrock \
  --connection-string "postgresql://my_user:my_pass@localhost:5432/mydb"
```

## Advanced Configuration

### Reasoning Mode

Enable Claude's "thinking" mode for complex reasoning tasks:

```bash
./gateway discover \
  --ai-provider bedrock \
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
  --ai-provider bedrock \
  --ai-max-tokens 8192 \
  --connection-string "postgresql://my_user:my_pass@localhost:5432/mydb"
```

If not specified, the default maximum token count is 64000 tokens.

### Temperature Adjustment

Adjust the randomness of responses with the temperature parameter:

```bash
./gateway discover \
  --ai-provider bedrock \
  --ai-temperature 0.5 \
  --connection-string "postgresql://my_user:my_pass@localhost:5432/mydb"
```

Lower values produce more deterministic outputs, while higher values increase creativity and randomness.

## Usage Costs

The Bedrock provider includes cost estimation for Claude Sonnet models:

- **Input tokens:** $3.75 per 1 million tokens
- **Output tokens:** $15.00 per 1 million tokens

Costs are calculated based on the actual token usage for each request.

## Recommended Best Practices

- **Start with Claude 3.7 Sonnet:** Offers a balance of performance and cost.
- **Manage Token Count:** Set a reasonable maximum token count to control costs.
- **Enable Reasoning Mode:** Use for complex analytical tasks.
- **Secure Configuration:** Use environment variables or AWS credentials files for sensitive settings.
- **Regularly Update IAM Policies:** Follow the principle of least privilege to minimize risks.

## Additional Resources

- [AWS Identity and Access Management (IAM) Documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/introduction.html)
- [AWS Security Credentials](https://docs.aws.amazon.com/general/latest/gr/aws-security-credentials.html)
- [AWS CLI Official Documentation](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html)
