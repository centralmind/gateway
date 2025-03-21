package elasticsearch

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/centralmind/gateway/castx"
	"github.com/centralmind/gateway/connectors"
	"github.com/centralmind/gateway/model"
	"github.com/elastic/go-elasticsearch/v8"
	"golang.org/x/xerrors"
	"io"
	"strings"
)

const limitOfDocuments = 5

func init() {
	connectors.Register(func(cfg Config) (connectors.Connector, error) {
		config, err := cfg.MakeConfig()
		if err != nil {
			return nil, xerrors.Errorf("unable to prepare Elasticsearch config: %w", err)
		}
		client, err := elasticsearch.NewClient(*config)
		if err != nil {
			return nil, xerrors.Errorf("unable to create Elasticsearch client: %w", err)
		}
		return &Connector{
			config: cfg,
			client: client,
		}, nil
	})
}

var _ connectors.Connector = (*Connector)(nil)

// Connector implements the connectors.Connector interface for Elasticsearch
type Connector struct {
	config Config
	client *elasticsearch.Client
}

func (c *Connector) Config() connectors.Config {
	return &c.config
}

// Ping checks if Elasticsearch is reachable
func (c *Connector) Ping(ctx context.Context) error {
	res, err := c.client.Ping(c.client.Ping.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("failed to ping Elasticsearch: %w", err)
	}
	defer res.Body.Close()
	return nil
}

// Query executes a search query in Elasticsearch
func (c *Connector) Query(ctx context.Context, endpoint model.Endpoint, params map[string]any) ([]map[string]any, error) {
	processed, err := castx.ParamsE(endpoint, params)
	if err != nil {
		return nil, xerrors.Errorf("unable to process params: %w", err)
	}

	finalQuery := map[string]interface{}{
		"source": endpoint.Query,
		"params": processed,
	}

	var buf bytes.Buffer
	err = json.NewEncoder(&buf).Encode(finalQuery)
	if err != nil {
		return nil, xerrors.Errorf("unable to encode query: %w", err)
	}

	res, err := c.client.API.SearchTemplate(
		&buf,
		c.client.SearchTemplate.WithContext(ctx),
	)
	if err != nil {
		return nil, xerrors.Errorf("failed to execute search query: %w", err)
	}

	defer res.Body.Close()

	// Read response body
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, xerrors.Errorf("failed to read Elasticsearch response: %w", err)
	}

	// Check for errors
	if res.IsError() {
		return nil, xerrors.Errorf("Elasticsearch returned an error: %s", body)
	}

	// Parse JSON response
	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse Elasticsearch response: %w", err)
	}

	var hits []interface{}
	if hitsMap, ok := result["hits"].(map[string]interface{}); ok {
		if hitsList, ok := hitsMap["hits"].([]interface{}); ok {
			hits = hitsList
		} else {
			return nil, xerrors.Errorf("'hits' key is missing or not a list")
		}
	} else {
		return nil, xerrors.Errorf("'hits' key is missing or not a map")
	}
	// Process the results
	results := make([]map[string]interface{}, 0)
	for _, hit := range hits {
		hitMap, ok := hit.(map[string]interface{})
		if !ok {
			continue
		}

		source, ok := hitMap["_source"].(map[string]interface{})
		if !ok {
			continue
		}

		results = append(results, source)
	}

	return results, nil
}

// Discovery retrieves available indices in Elasticsearch
func (c *Connector) Discovery(ctx context.Context) ([]model.Table, error) {
	// Get a list of indices, but limit processing for large indices
	res, err := c.client.Cat.Indices(
		c.client.Cat.Indices.WithContext(ctx),
		c.client.Cat.Indices.WithFormat("json"),
	)
	if err != nil {
		return nil, xerrors.Errorf("failed to get indices: %w", err)
	}
	defer res.Body.Close()

	// Read response body
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, xerrors.Errorf("failed to read indices response: %w", err)
	}

	// Parse JSON response
	var indices []map[string]interface{}
	if err := json.Unmarshal(body, &indices); err != nil {
		return nil, xerrors.Errorf("failed to parse indices response: %w", err)
	}
	// Process only a subset of indices (if necessary)
	var tables []model.Table
	for _, index := range indices {
		indexName, ok := index["index"].(string)
		if !ok {
			continue
		}

		// Instead of fetching all mappings, **sample documents** to infer fields
		columns, err := c.sampleIndexFields(ctx, indexName)
		if err != nil {
			return nil, xerrors.Errorf("failed to infer schema for index %s: %w", indexName, err)
		}

		// Get document count efficiently
		rowCount, err := c.getDocumentCount(ctx, indexName)
		if err != nil {
			return nil, xerrors.Errorf("failed to get row count for index %s: %w", indexName, err)
		}

		tables = append(tables, model.Table{
			Name:     indexName,
			Columns:  columns,
			RowCount: rowCount,
		})
	}

	return tables, nil
}

func (c *Connector) getDocumentCount(ctx context.Context, indexName string) (int, error) {
	// Execute _count API request
	res, err := c.client.Count(
		c.client.Count.WithContext(ctx),
		c.client.Count.WithIndex(indexName),
	)
	if err != nil {
		return 0, xerrors.Errorf("failed to execute _count API: %w", err)
	}
	defer res.Body.Close()

	// Read response body
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return 0, xerrors.Errorf("failed to read _count response: %w", err)
	}

	// Parse JSON response
	var countResponse map[string]interface{}
	if err := json.Unmarshal(body, &countResponse); err != nil {
		return 0, xerrors.Errorf("failed to parse _count response: %w", err)
	}

	// Extract document count
	count, ok := countResponse["count"].(float64)
	if !ok {
		return 0, xerrors.Errorf("unexpected _count response format")
	}

	return int(count), nil
}

// Sample retrieves a few sample documents from an index
func (c *Connector) Sample(ctx context.Context, table model.Table) ([]map[string]any, error) {
	query := map[string]interface{}{
		"size": limitOfDocuments,
		"query": map[string]interface{}{
			"match_all": map[string]interface{}{},
		},
	}

	// Convert query to JSON
	queryBytes, err := json.Marshal(query)
	if err != nil {
		return nil, xerrors.Errorf("failed to marshal sample query: %w", err)
	}

	// Execute the search request
	res, err := c.client.Search(
		c.client.Search.WithContext(ctx),
		c.client.Search.WithBody(bytes.NewReader(queryBytes)),
	)
	if err != nil {
		return nil, xerrors.Errorf("failed to fetch sample documents: %w", err)
	}
	defer res.Body.Close()

	// Read response body
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, xerrors.Errorf("failed to read sample response: %w", err)
	}

	// Parse JSON response
	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse sample response: %w", err)
	}

	// Extract search hits
	var hits []interface{}
	if hitsMap, ok := result["hits"].(map[string]interface{}); ok {
		if hitsList, ok := hitsMap["hits"].([]interface{}); ok {
			hits = hitsList
		} else {
			return nil, xerrors.Errorf("'hits' key is missing or not a list")
		}
	} else {
		return nil, xerrors.Errorf("'hits' key is missing or not a map")
	}

	// Process the results
	results := make([]map[string]interface{}, len(hits))
	for i, hit := range hits {
		hitMap := hit.(map[string]interface{})
		results[i] = hitMap["_source"].(map[string]interface{})
	}

	return results, nil
}

func (c *Connector) InferQuery(ctx context.Context, query string) ([]model.ColumnSchema, error) {
	// Query multiple documents for better inference
	// Ensure the query is properly formatted JSON
	var esQuery map[string]interface{}
	err := json.Unmarshal([]byte(query), &esQuery)
	if err != nil {
		return nil, xerrors.Errorf("invalid query format: %w", err)
	}

	// Execute the query in Elasticsearch
	res, err := c.client.Search(
		c.client.Search.WithContext(ctx),
		c.client.Search.WithBody(strings.NewReader(query)),
	)
	if err != nil {
		return nil, xerrors.Errorf("failed to execute query: %w", err)
	}
	defer res.Body.Close()

	// Read response body
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, xerrors.Errorf("failed to read Elasticsearch response: %w", err)
	}

	// Parse JSON response
	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse Elasticsearch response: %w", err)
	}

	// Extract "hits" (documents)
	var hits []interface{}
	if hitsMap, ok := result["hits"].(map[string]interface{}); ok {
		if hitsList, ok := hitsMap["hits"].([]interface{}); ok {
			hits = hitsList
		} else {
			return nil, xerrors.Errorf("'hits' key is missing or not a list")
		}
	} else {
		return nil, xerrors.Errorf("'hits' key is missing or not a map")
	}
	// Use the helper function
	return c.extractColumnsFromHits(hits)
}

func (c *Connector) GuessColumnType(sqlType string) model.ColumnType {
	switch strings.ToLower(sqlType) {
	case "text", "keyword":
		return model.TypeString
	case "long", "integer", "short", "byte":
		return model.TypeInteger
	case "float", "double", "half_float", "scaled_float":
		return model.TypeNumber
	case "boolean":
		return model.TypeBoolean
	case "date":
		return model.TypeDatetime
	case "object", "nested":
		return model.TypeObject
	case "array":
		return model.TypeArray
	default:
		return model.TypeString // Default fallback
	}
}

func (c *Connector) sampleIndexFields(ctx context.Context, indexName string) ([]model.ColumnSchema, error) {
	N := 100 // Sample up to 100 documents
	query := map[string]interface{}{
		"size": N,
		"query": map[string]interface{}{
			"match_all": map[string]interface{}{},
		},
	}

	// Convert query to JSON
	queryBytes, err := json.Marshal(query)
	if err != nil {
		return nil, xerrors.Errorf("failed to marshal sample query: %w", err)
	}

	// Execute search request
	res, err := c.client.Search(
		c.client.Search.WithContext(ctx),
		c.client.Search.WithIndex(indexName),
		c.client.Search.WithBody(bytes.NewReader(queryBytes)),
	)
	if err != nil {
		return nil, xerrors.Errorf("failed to execute sample query: %w", err)
	}
	defer res.Body.Close()

	// Read response body
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, xerrors.Errorf("failed to read search response: %w", err)
	}

	// Parse JSON response
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, xerrors.Errorf("failed to parse search response: %w", err)
	}

	// Extract search hits (sample documents)
	hits, ok := result["hits"].(map[string]interface{})["hits"].([]interface{})
	if !ok {
		return nil, xerrors.Errorf("unexpected response structure from Elasticsearch")
	}

	// Use the helper function
	return c.extractColumnsFromHits(hits)
}

func (c *Connector) extractColumnsFromHits(hits []interface{}) ([]model.ColumnSchema, error) {
	// Track field types across multiple documents
	fieldTypeMap := make(map[string]string)

	// Iterate through sample documents
	for _, hit := range hits {
		doc, ok := hit.(map[string]interface{})["_source"].(map[string]interface{})
		if !ok {
			continue
		}

		for field, value := range doc {
			fieldType := fmt.Sprintf("%T", value) // Get Go type as a string
			if _, exists := fieldTypeMap[field]; !exists {
				fieldTypeMap[field] = fieldType
			}
		}
	}

	// Convert detected types to ColumnSchema
	var columns []model.ColumnSchema
	for field, detectedType := range fieldTypeMap {
		columnType := c.GuessColumnType(detectedType) // Convert to SQL-like type
		columns = append(columns, model.ColumnSchema{
			Name: field,
			Type: columnType,
		})
	}

	return columns, nil
}
