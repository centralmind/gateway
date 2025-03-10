# BigQuery Connector

This connector allows you to connect to Google BigQuery and execute queries against your datasets.

## Configuration

The connector requires the following configuration parameters:

- `type` (string): Constant - `bigquery`
- `project_id` (string): Your Google Cloud Project ID
- `dataset` (string): The BigQuery dataset name
- `credentials` (string): Google Cloud service account credentials JSON as a string

## Example Configuration

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

## Features

- Table discovery
- Query execution with parameters
- Schema inference
- Row sampling

## Limitations

- BigQuery doesn't support traditional primary keys
- Credentials must be provided as a JSON string
- Some BigQuery-specific features like clustering and partitioning are not exposed through this connector 
