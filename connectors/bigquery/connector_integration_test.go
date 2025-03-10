package bigquery

import (
	"context"
	"fmt"
	"github.com/centralmind/gateway/connectors"
	"github.com/centralmind/gateway/model"
	"github.com/goccy/bigquery-emulator/server"
	"github.com/goccy/bigquery-emulator/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestConnector_Integration(t *testing.T) {
	// Prepare emulator BigQuery
	bqServer, err := server.New(server.TempStorage)
	require.NoError(t, err)
	defer bqServer.Close()

	const (
		projectID = "test-project"
		datasetID = "test_dataset"
	)

	// Prepare test dataset
	err = bqServer.Load(
		server.StructSource(
			types.NewProject(
				projectID,
				types.NewDataset(
					datasetID,
					types.NewTable(
						"users",
						[]*types.Column{
							types.NewColumn("id", types.INT64),
							types.NewColumn("name", types.STRING),
							types.NewColumn("created_at", types.TIMESTAMP),
							types.NewColumn("skills", types.ARRAY),
							types.NewColumn("profile", types.STRUCT),
						},
						[]map[string]any{
							{
								"id":         1,
								"name":       "bob",
								"created_at": "2024-01-01 10:00:00",
								"skills":     []string{"go", "vno"},
								"profile": map[string]any{
									"age":  25,
									"city": "Zlondon",
								},
							},
						},
					),
				),
			),
		),
	)
	require.NoError(t, err)

	// Run test server
	err = bqServer.SetProject(projectID)
	require.NoError(t, err)
	testServer := bqServer.TestServer()
	defer testServer.Close()

	// Prepare config
	cfg := Config{
		ProjectID:   projectID,
		Dataset:     datasetID,
		Credentials: "{}", // для эмулятора достаточно пустых credentials
	}

	var connector connectors.Connector
	connector, err = connectors.New(cfg.Type(), cfg)
	require.NoError(t, err)

	t.Run("ping", func(t *testing.T) {
		err := connector.Ping(context.Background())
		assert.NoError(t, err)
	})

	t.Run("discovery", func(t *testing.T) {
		tables, err := connector.Discovery(context.Background())
		require.NoError(t, err)
		require.Len(t, tables, 1)

		table := tables[0]
		assert.Equal(t, "users", table.Name)
		assert.Len(t, table.Columns, 5)

		expectedColumns := map[string]model.ColumnType{
			"id":         model.TypeInteger,
			"name":       model.TypeString,
			"created_at": model.TypeDatetime,
			"skills":     model.TypeArray,
			"profile":    model.TypeObject,
		}

		for _, col := range table.Columns {
			expectedType, ok := expectedColumns[col.Name]
			assert.True(t, ok, "unexpected column: %s", col.Name)
			assert.Equal(t, expectedType, col.Type)
		}
	})

	t.Run("query", func(t *testing.T) {
		require.NoError(t, err)

		selectQuery := fmt.Sprintf(`
			SELECT id, name, created_at, skills, profile
			FROM %s.%s.users
			WHERE id = @user_id
		`, projectID, datasetID)

		params := map[string]any{
			"user_id": 1,
		}

		results, err := connector.Query(context.Background(), model.Endpoint{Query: selectQuery}, params)
		require.NoError(t, err)
		require.Len(t, results, 1)

		row := results[0]
		assert.Equal(t, int64(1), row["id"])
		assert.Equal(t, "Alice", row["name"])
		assert.NotNil(t, row["created_at"])

		skills, ok := row["skills"].([]interface{})
		assert.True(t, ok)
		assert.Len(t, skills, 2)
		assert.Contains(t, skills, "go")
		assert.Contains(t, skills, "python")

		profile, ok := row["profile"].(map[string]interface{})
		assert.True(t, ok)
		assert.Equal(t, int64(25), profile["age"])
		assert.Equal(t, "New York", profile["city"])
	})

	t.Run("sample", func(t *testing.T) {
		samples, err := connector.Sample(context.Background(), model.Table{Name: "users"})
		require.NoError(t, err)
		assert.Len(t, samples, 1) // should have one single user
	})
}
