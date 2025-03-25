package mongodb

import (
	"context"
	"fmt"
	"testing"

	"github.com/centralmind/gateway/connectors"
	"github.com/centralmind/gateway/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestMongoDBConnector(t *testing.T) {
	ctx := context.Background()

	// Create MongoDB container
	mongoContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "mongo:latest",
			ExposedPorts: []string{"27017/tcp"},
			Env: map[string]string{
				"MONGO_INITDB_ROOT_USERNAME": "admin",
				"MONGO_INITDB_ROOT_PASSWORD": "password",
			},
			WaitingFor: wait.ForLog("Waiting for connections"),
		},
		Started: true,
	})
	require.NoError(t, err)
	defer func() {
		require.NoError(t, mongoContainer.Terminate(ctx))
	}()

	// Get mapped port
	mappedPort, err := mongoContainer.MappedPort(ctx, "27017")
	require.NoError(t, err)

	// Update config with container details
	cfg := Config{
		Hosts:    []string{fmt.Sprintf("localhost:%s", mappedPort.Port())},
		Database: "testdb",
		Username: "admin",
		Password: "password",
	}

	// Create connector
	connector, err := connectors.New("mongodb", cfg)
	require.NoError(t, err)
	assert.NotNil(t, connector)

	// Insert test data
	db := connector.(*Connector).client.Database(cfg.Database)
	collection := db.Collection("test_collection")
	_, err = collection.InsertOne(ctx, map[string]interface{}{
		"name": "test",
		"age":  30,
	})
	require.NoError(t, err)

	t.Run("Ping Database", func(t *testing.T) {
		err := connector.Ping(ctx)
		assert.NoError(t, err)
	})

	t.Run("Discovery Collections", func(t *testing.T) {
		tables, err := connector.Discovery(ctx)
		assert.NoError(t, err)
		assert.NotEmpty(t, tables)

		found := false
		for _, table := range tables {
			if table.Name == "test_collection" {
				found = true
				break
			}
		}
		assert.True(t, found, "Expected collection 'test_collection' to exist")
	})

	t.Run("Query Documents", func(t *testing.T) {
		endpoint := model.Endpoint{
			Query: `{
				"collection": "test_collection",
				"filter": {
					"name": "@name"
				}
			}`,
			Params: []model.EndpointParams{
				{Name: "name", Type: "string", Required: true},
			},
		}

		params := map[string]any{
			"name": "test",
		}

		rows, err := connector.Query(ctx, endpoint, params)
		assert.NoError(t, err)
		assert.Len(t, rows, 1)
		assert.Equal(t, "test", rows[0]["name"])
		assert.Equal(t, int32(30), rows[0]["age"])
	})

	t.Run("Sample Data", func(t *testing.T) {
		samples, err := connector.Sample(ctx, model.Table{Name: "test_collection"})
		assert.NoError(t, err)
		assert.Len(t, samples, 1)
		assert.Equal(t, "test", samples[0]["name"])
		assert.Equal(t, int32(30), samples[0]["age"])
	})
}

func TestMongoDBTypeMapping(t *testing.T) {
	c := &Connector{}

	tests := []struct {
		name      string
		mongoType string
		expected  model.ColumnType
	}{
		{"string", "string", model.TypeString},
		{"number", "number", model.TypeNumber},
		{"int", "int", model.TypeInteger},
		{"bool", "bool", model.TypeBoolean},
		{"date", "date", model.TypeDatetime},
		{"object", "object", model.TypeObject},
		{"array", "array", model.TypeArray},
		{"unknown", "unknown", model.TypeString},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := c.GuessColumnType(tt.mongoType)
			assert.Equal(t, tt.expected, result)
		})
	}
}
