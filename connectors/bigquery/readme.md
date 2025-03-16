---
title: 'BigQuery'
---

This connector allows you to connect to Google BigQuery and execute queries against your datasets.

## Config Schema

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| type | string | yes | constant: `bigquery` |
| project_id | string | yes | Your Google Cloud Project ID |
| dataset | string | yes | The BigQuery dataset name |
| credentials | string | yes | Google Cloud service account credentials JSON |
| endpoint | string | no | Custom BigQuery API endpoint (for testing) |
| conn_string | string | no | JSON-formatted connection string with all parameters |

## Config example:

```yaml
type: bigquery
project_id: your-project-id
dataset: your_dataset
credentials: |
  {
    "type": "service_account",
    ...
  }
```

Or as alternative with JSON-formatted connection string:

```yaml
type: bigquery
conn_string: |
  {
    "project_id": "your-project-id",
    "dataset": "your_dataset",
    "credentials": {
      "type": "service_account",
      ...
    }
  }
```

## Features

- Table discovery
- Query execution with parameters
- Schema inference
- Row sampling

## Service Account Setup

To use this connector, you'll need to set up a Google Cloud service account with appropriate permissions:

#### 1. Go to Google Cloud Console  
- Open [Google Cloud Console](https://console.cloud.google.com/).  
- Select the project you want to access.  

#### 2. Create a Service Account  
- Navigate to **IAM & Admin** → **Service Accounts** ([direct link](https://console.cloud.google.com/iam-admin/serviceaccounts)).  
- Click **Create Service Account**.  
- Enter the **account name** and **description**, then click **Create**.  
- In the **Grant this service account access to the project** section, add the following roles:  
  - `BigQuery Data Viewer` (view data)  
  - `BigQuery Metadata Viewer` (to be able get meta information about tables)  
  - `BigQuery Job User` (to be able execute queries)  
- Click **Done**. 

![img](../assets/bigquery-permissions.webp)

#### 3. Create a JSON Key  
- Find the newly created service account in the list.  
- Open its page and go to the **Keys** tab.  
- Click **Add Key** → **Create new key**.  
- Select **JSON** and click **Create**.  
- The credentials file will be automatically downloaded (`your-project-key.json`).  

## Limitations

- BigQuery doesn't support traditional primary keys
- Credentials must be provided as a JSON string
- Some BigQuery-specific features like clustering and partitioning are not exposed through this connector
