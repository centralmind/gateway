This guide will help you get started with Gateway using Docker, discover your database and launch API on top of it.

## Prerequisites

- <a href="https://platform.openai.com/api-keys">OpenAI API key</a> for AI-powered API generation
- Your PostgreSQL Database or any other db that gateway supports. You can also take our example databases:
  - <a href="/example/postgresql-dvdstore-sample/">PostgreSQL DVD Store Sample Database</a>.
  - <a href="/example/postgresql-ecommerce-sample/">PostgreSQL Ecommerce Sample Database</a>.

## Installation and Launching Steps

### 1. Binary Installation

Choose your operating system below for specific installation instructions for Linux:

```bash
# Download the latest binary for Linux
wget https://github.com/centralmind/gateway/releases/latest/download/gateway-linux-amd64.tar.gz

# Extract the archive
tar -xzf gateway-linux-amd64.tar.gz
mv gateway-linux-amd64 gateway

# Make the binary executable
chmod +x gateway
```

<details>
<summary>Windows (Intel)</summary>

```powershell
# Download the latest binary for Windows
Invoke-WebRequest -Uri https://github.com/centralmind/gateway/releases/latest/download/gateway-windows-amd64.zip -OutFile gateway-windows.zip

# Extract the archive
Expand-Archive -Path gateway-windows.zip -DestinationPath .

# Rename
Rename-Item -Path "gateway-windows-amd64.exe" -NewName "gateway.exe"

```

</details>

<details>
<summary>macOS (Intel)</summary>

```bash
# Download the latest binary for macOS (Intel)
curl -LO https://github.com/centralmind/gateway/releases/latest/download/gateway-darwin-amd64.tar.gz

# Extract the archive
tar -xzf gateway-darwin-amd64.tar.gz
mv gateway-darwin-amd64 gateway

# Make the binary executable
chmod +x gateway

```

</details>

<details>
<summary>macOS (Apple Silicon)</summary>
 
```bash
# Download the latest binary for macOS (Apple Silicon)
curl -LO https://github.com/centralmind/gateway/releases/latest/download/gateway-darwin-arm64.tar.gz

# Extract the archive

tar -xzf gateway-darwin-arm64.tar.gz
mv gateway-darwin-arm64 gateway

# Make the binary executable

chmod +x gateway

````
</details>


### 2. Choose one of our supported AI providers:

- [OpenAI](/providers/openai) and all OpenAI-compatible providers
- [Anthropic](/providers/anthropic)
- [Amazon Bedrock](/providers/bedrock)
- [Google Vertex AI (Anthropic)](/providers/anthropic-vertexai)
- [Google Gemini](/providers/gemini)

[Google Gemini](https://docs.centralmind.ai/providers/gemini) provides a generous **free tier**. You can obtain an API key by visiting Google AI Studio:

- [Google AI Studio](https://aistudio.google.com/apikey)

Once logged in, you can create an API key in the API section of AI Studio. The free tier includes a generous monthly token allocation, making it accessible for development and testing purposes.

Configure AI provider authorization. For Google Gemini, set an API key.

```bash
export GEMINI_API_KEY='yourkey'
```

### 3. Run the discovery process with AI-powered API generation:

```bash
./gateway discover \
  --ai-provider gemini \
  --connection-string "postgresql://my_user:my_pass@localhost:5432/mydb" \
  --prompt "Develop an API that enables a chatbot to retrieve information about data. \
Try to place yourself as analyst and think what kind of data you will require, \
based on that come up with useful API methods for that"
```

### 4. Start the REST server:

```bash
./gateway --config gateway.yaml start
```

## Verification

After starting the REST server, you can verify the installation by accessing the Swagger UI:

```
http://localhost:9090/swagger/
```
