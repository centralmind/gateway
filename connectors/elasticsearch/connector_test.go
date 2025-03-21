package elasticsearch

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/centralmind/gateway/model"
	"github.com/docker/go-connections/nat"
	"github.com/sirupsen/logrus"
	"strconv"
	"testing"
	"time"

	"github.com/centralmind/gateway/connectors"
	es "github.com/elastic/go-elasticsearch/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/elasticsearch"
)

func TestElasticsearchConnectorWithAuth(t *testing.T) {
	ctx := context.Background()
	esPassword := "test"
	esUserName := "elastic"

	esContainer, err := elasticsearch.Run(ctx,
		"docker.elastic.co/elasticsearch/elasticsearch:8.6.2",
		elasticsearch.WithPassword(esPassword),
	)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, esContainer.Terminate(ctx))
	}()
	esPort, _ := esContainer.MappedPort(ctx, nat.Port("9200"))
	esURL := fmt.Sprintf("http://localhost:%s", esPort.Port())
	logrus.Info("Elasticsearch URL:", esURL)

	cfg := Config{
		Hosts: []string{
			esContainer.Settings.Address,
		},
		Username:  "elastic",
		Password:  esContainer.Settings.Password,
		EnableTLS: true,
		CertFile:  string(esContainer.Settings.CACert),
	}

	connector, err := connectors.New("elasticsearch", cfg)
	assert.NoError(t, err)
	assert.NotNil(t, connector)

	// Create test index and insert sample data
	t.Run("Setup Test Data", func(t *testing.T) {
		esClient, err := es.NewClient(es.Config{
			Addresses: []string{
				esContainer.Settings.Address,
			},
			Username: esUserName,
			Password: esContainer.Settings.Password,
			CACert:   esContainer.Settings.CACert,
		})
		require.NoError(t, err)

		// Create index with mapping
		mapping := `{
			"mappings": {
				"properties": {
					"name": {"type": "text"},
					"age": {"type": "integer"},
					"city": {"type": "text"},
					"job": {"type": "text"},
					"created_at": {"type": "date"}
				}
			}
		}`
		_, err = esClient.Indices.Create("test_users", esClient.Indices.Create.WithBody(bytes.NewReader([]byte(mapping))))
		require.NoError(t, err)

		// Insert sample documents
		sampleDocs := []map[string]interface{}{
			{"name": "Alice", "age": 28, "city": "New York", "job": "Engineer", "created_at": "2024-03-12T12:00:00Z"},
			{"name": "Bob", "age": 35, "city": "San Francisco", "job": "Designer", "created_at": "2024-03-11T10:30:00Z"},
		}
		for i, doc := range sampleDocs {
			docJSON, _ := json.Marshal(doc)
			docID := strconv.Itoa(i + 1) // ✅ Convert i+1 to string
			_, err := esClient.Index("test_users", bytes.NewReader(docJSON), esClient.Index.WithDocumentID(docID))
			require.NoError(t, err)
		}
	})

	// Test: Ping Elasticsearch
	t.Run("Ping Elasticsearch", func(t *testing.T) {
		err := connector.Ping(ctx)
		assert.NoError(t, err)
	})

	// Test: Discover Indices
	t.Run("Discover Indices", func(t *testing.T) {
		indices, err := connector.Discovery(ctx)
		assert.NoError(t, err)
		assert.NotEmpty(t, indices)

		found := false
		for _, index := range indices {
			if index.Name == "test_users" {
				found = true
				break
			}
		}
		assert.True(t, found, "Expected index 'test_users' to exist")
	})

	// Test: Query Elasticsearch
	t.Run("Query Documents", func(t *testing.T) {
		// When you insert documents, they are not immediately searchable.
		// Elasticsearch requires a short period to index the data.
		time.Sleep(2.0 * time.Second)
		endpoint := model.Endpoint{
			Query: `{
					"query": {
						"match": {
							"job": "{{job}}"
						}
					}
				}`,
			Params: []model.EndpointParams{
				{Name: "job", Type: "string", Required: true},
			},
		}

		params := map[string]any{
			"job": "Engineer",
		}

		rows, err := connector.Query(ctx, endpoint, params)
		assert.NoError(t, err)
		assert.Len(t, rows, 1)

		expected := map[string]any{
			"name":       "Alice",
			"age":        float64(28), // JSON numbers default to float64 in Go
			"city":       "New York",
			"job":        "Engineer",
			"created_at": "2024-03-12T12:00:00Z",
		}
		assert.Equal(t, expected, rows[0])
	})
}
