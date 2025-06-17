---
title: Using Locally Running Models
description: Guide to using locally running models with Gateway using LM Studio
---

This guide explains how to set up and use locally running models with Gateway using LM Studio.

## 1. Installing LM Studio

1. Go to the [LM Studio website](https://lmstudio.ai/download) and download the version suitable for your operating system.
2. Install LM Studio by following the installer's instructions.

## 2. Setting Up a Model in LM Studio

1. Launch LM Studio after installation.
2. Navigate to the "Model Catalog" section.
3. Choose a suitable model for your tasks. It's recommended to select models that support OpenAI-compatible API.
4. Click the "Download" button for the selected model.
5. Wait for the model download and installation to complete.

## 3. Starting the Server in LM Studio

1. In LM Studio, navigate to the "Developers" tab.
2. In the "Local Inference Server" section, select your installed model from the dropdown menu.
3. Click the "Start Server" button.
4. After the server starts, you will see information about the API endpoint. It will look something like:
   ```
   Server running at: http://localhost:1234/v1
   ```
5. Also note the model name displayed in the interface.
   ```
    This model's API identifier: llama3-8b
   ```

## 4. Running Gateway with Parameters for Local Model

1. Copy the API endpoint URL from LM Studio (for example, `http://localhost:1234/v1`).
2. Copy the model name (for example, `llama3-8b`).
3. Run Gateway with the `--ai-endpoint` and `--ai-model` parameters, specifying the copied values:

```bash
gateway discover \
  --ai-endpoint "http://localhost:1234/v1" \
  --connection-string "postgresql://my_user:my_pass@localhost:5432/mydb" \
  --ai-model "llama3-8b" \
  --prompt "Develop an API that enables a chatbot to retrieve information about data. \
Try to place yourself as analyst and think what kind of data you will require, \
based on that come up with useful API methods for that"

```

Where:

- `--ai-endpoint` - The API endpoint URL copied from LM Studio
- `--ai-model` - The name of the model selected in LM Studio
- `--prompt` - Extra prompt where you can explain additional requirements for API methods

## 5. Benefits and Considerations

### Benefits:

- **Offline Operation**: Work completely offline, without internet access
- **Data Privacy**: Ensure data confidentiality as it remains within your local network
- **Cost Reduction**: Lower costs by not using cloud APIs
- **Customization**: Fine-tune local models for specific needs

### Considerations:

- **Quality**: Small models unfortunatly does not produce sustainable JSON configurations therefore use models starting with 32B parameters like Qwen2.5-32B or Qwen2.5-32B-Instruct
- **Performance**: The performance of locally running models depends on your computer's specifications. For large models, a computer with a powerful GPU is recommended.
- **Port Availability**: Ensure that the port used by LM Studio is not blocked by firewalls or other programs.
- **Custom Prompts**: If you want to use other parameters for API generation, you can add the `--prompt` parameter with your own request.

## Starting API Server

After creation of API configuration you can launch API server. To do this, run:

```bash
./gateway start rest --config gateway.yaml
```

Now you can use Gateway with locally running models through LM Studio!
