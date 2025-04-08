package bigquery

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"testing"

	"github.com/centralmind/gateway/connectors"
	"github.com/centralmind/gateway/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/gcloud"
)

//go:embed testdata/data.yaml
var dataYaml []byte

func TestConnector_Integration(t *testing.T) {
	ctx := context.Background()

	// Start BigQuery emulator container
	bigQueryContainer, err := gcloud.RunBigQuery(
		ctx,
		"ghcr.io/goccy/bigquery-emulator:0.6.6",
		gcloud.WithProjectID("test-project"),
		gcloud.WithDataYAML(bytes.NewReader(dataYaml)),
	)
	require.NoError(t, err)
	defer func() {
		if err := bigQueryContainer.Terminate(ctx); err != nil {
			t.Logf("failed to terminate container: %s", err)
		}
	}()

	const (
		projectID = "test-project"
		datasetID = "test_dataset"
	)

	// Prepare config
	cfg := Config{
		ProjectID:   projectID,
		Dataset:     datasetID,
		Endpoint:    bigQueryContainer.URI,
		Credentials: "{}",
	}

	var connector connectors.Connector
	connector, err = connectors.New(cfg.Type(), cfg)
	require.NoError(t, err)

	t.Run("ping", func(t *testing.T) {
		err := connector.Ping(ctx)
		assert.NoError(t, err)
	})

	t.Run("discovery", func(t *testing.T) {
		t.Skip("TODO: implement discovery test-container")
		tables, err := connector.Discovery(ctx, nil)
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
		selectQuery := fmt.Sprintf(`
			SELECT id, name, created_at
			FROM %s.%s.users
			WHERE id = @user_id
		`, projectID, datasetID)

		params := map[string]any{
			"user_id": 1,
		}

		results, err := connector.Query(
			ctx,
			model.Endpoint{
				Query: selectQuery,
				Params: []model.EndpointParams{
					{
						Name: "user_id",
						Type: string(model.TypeInteger),
					},
				},
			},
			params,
		)
		require.NoError(t, err)
		require.Len(t, results, 1)

		row := results[0]
		assert.Equal(t, int64(1), row["id"])
		assert.Equal(t, "alice", row["name"])
		assert.NotNil(t, row["created_at"])
	})

	t.Run("sample", func(t *testing.T) {
		samples, err := connector.Sample(ctx, model.Table{Name: "users"})
		require.NoError(t, err)
		assert.Len(t, samples, 2) // should have 2 users
	})

	t.Run("limit and offset", func(t *testing.T) {
		selectQuery := fmt.Sprintf(`
			SELECT id, name
			FROM %s.%s.users
			ORDER BY id
			LIMIT @limit
			OFFSET @offset
		`, projectID, datasetID)

		params := map[string]any{
			"limit":  1,
			"offset": 1,
		}

		results, err := connector.Query(
			ctx,
			model.Endpoint{
				Query: selectQuery,
				Params: []model.EndpointParams{
					{
						Name: "limit",
						Type: string(model.TypeInteger),
					},
					{
						Name: "offset",
						Type: string(model.TypeInteger),
					},
				},
			},
			params,
		)
		require.NoError(t, err)
		require.Len(t, results, 1)

		// Should get second user due to OFFSET 1
		row := results[0]
		assert.Equal(t, int64(30), row["id"])
	})
}
