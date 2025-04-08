package duckdb

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/centralmind/gateway/connectors"
	"github.com/centralmind/gateway/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConnector(t *testing.T) {
	ctx := context.Background()

	// Use in-memory database
	cfg := Config{
		Memory: true,
	}

	// Verify that the connection string is ":memory:"
	connStr := cfg.ConnectionString()
	assert.Equal(t, ":memory:", connStr)

	connector, err := connectors.New("duckdb", cfg)
	require.NoError(t, err)
	require.NotNil(t, connector)

	// Create test tables and insert data from SQL file
	db := connector.(*Connector).db

	// First drop tables if they exist to avoid duplicate key errors
	_, err = db.Exec("DROP TABLE IF EXISTS posts")
	require.NoError(t, err)
	_, err = db.Exec("DROP TABLE IF EXISTS users")
	require.NoError(t, err)

	// Then create and populate tables
	sqlData, err := os.ReadFile(filepath.Join("testdata", "test_data.sql"))
	require.NoError(t, err)
	_, err = db.Exec(string(sqlData))
	require.NoError(t, err)

	t.Run("Ping Database", func(t *testing.T) {
		err := connector.Ping(ctx)
		assert.NoError(t, err)
	})

	t.Run("Discovery Tables", func(t *testing.T) {
		tables, err := connector.Discovery(ctx, nil)
		require.NoError(t, err)
		require.Len(t, tables, 2)

		// Verify table names
		tableNames := make(map[string]bool)
		for _, table := range tables {
			tableNames[table.Name] = true
		}
		assert.True(t, tableNames["users"])
		assert.True(t, tableNames["posts"])
	})

	t.Run("Read Endpoint", func(t *testing.T) {
		endpoint := model.Endpoint{
			Query:  "SELECT COUNT(*) AS total_count FROM users",
			Params: []model.EndpointParams{},
		}
		params := map[string]any{}
		rows, err := connector.Query(ctx, endpoint, params)
		assert.NoError(t, err)
		assert.Len(t, rows, 1)

		// DuckDB might return int32 or int64 for counts, handle both
		totalCount := rows[0]["total_count"]
		switch v := totalCount.(type) {
		case int32:
			assert.Equal(t, int32(3), v)
		case int64:
			assert.Equal(t, int64(3), v)
		default:
			assert.Failf(t, "Unexpected type for total_count", "Got %T, expected int32 or int64", totalCount)
		}
	})

	t.Run("Query Endpoint with Parameters", func(t *testing.T) {
		endpoint := model.Endpoint{
			// Use CAST to ensure proper parameter typing in DuckDB
			Query: `SELECT name, age, email 
					FROM users 
					WHERE age > CAST(:min_age AS INTEGER) 
					ORDER BY age DESC`,
			Params: []model.EndpointParams{
				{
					Name:     "min_age",
					Type:     "int",
					Required: true,
				},
			},
		}
		params := map[string]any{
			"min_age": 25,
		}
		rows, err := connector.Query(ctx, endpoint, params)
		require.NoError(t, err)
		require.Len(t, rows, 2, "Expected 2 rows but got %d", len(rows))

		// Only check expected values if we have results
		if len(rows) == 2 {
			// DuckDB might return int32 instead of int64, so we need to check the type
			expectedNames := []string{"Bob Johnson", "John Doe"}
			expectedEmails := []string{"bob@example.com", "john@example.com"}
			expectedAges := []int{35, 30} // Base values for comparison

			for i, expected := range expectedNames {
				assert.Equal(t, expected, rows[i]["name"])
				assert.Equal(t, expectedEmails[i], rows[i]["email"])

				// Check age based on actual type
				switch age := rows[i]["age"].(type) {
				case int32:
					assert.Equal(t, int32(expectedAges[i]), age)
				case int64:
					assert.Equal(t, int64(expectedAges[i]), age)
				default:
					assert.Failf(t, "Unexpected type for age", "Got %T, expected int32 or int64", rows[i]["age"])
				}
			}
		}
	})

	// Clean up at the end
	_, err = db.Exec("DROP TABLE IF EXISTS posts")
	require.NoError(t, err)
	_, err = db.Exec("DROP TABLE IF EXISTS users")
	require.NoError(t, err)
}

func TestDuckDBTypeMapping(t *testing.T) {
	c := &Connector{}

	tests := []struct {
		name     string
		sqlType  string
		expected model.ColumnType
	}{
		// String types
		{"varchar", "VARCHAR", model.TypeString},
		{"char", "CHAR", model.TypeString},
		{"text", "TEXT", model.TypeString},
		{"string", "STRING", model.TypeString},
		{"enum", "ENUM", model.TypeString},
		{"uuid", "UUID", model.TypeString},

		// Numeric types
		{"decimal", "DECIMAL", model.TypeNumber},
		{"numeric", "NUMERIC", model.TypeNumber},
		{"float", "FLOAT", model.TypeNumber},
		{"double", "DOUBLE", model.TypeNumber},
		{"real", "REAL", model.TypeNumber},

		// Integer types
		{"integer", "INTEGER", model.TypeInteger},
		{"bigint", "BIGINT", model.TypeInteger},
		{"smallint", "SMALLINT", model.TypeInteger},
		{"tinyint", "TINYINT", model.TypeInteger},
		{"ubigint", "UBIGINT", model.TypeInteger},
		{"uinteger", "UINTEGER", model.TypeInteger},
		{"usmallint", "USMALLINT", model.TypeInteger},
		{"utinyint", "UTINYINT", model.TypeInteger},

		// Boolean type
		{"boolean", "BOOLEAN", model.TypeBoolean},

		// Date/Time types
		{"date", "DATE", model.TypeDatetime},
		{"time", "TIME", model.TypeDatetime},
		{"timestamp", "TIMESTAMP", model.TypeDatetime},
		{"timestamp with time zone", "TIMESTAMP WITH TIME ZONE", model.TypeDatetime},
		{"timestamp without time zone", "TIMESTAMP WITHOUT TIME ZONE", model.TypeDatetime},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := c.GuessColumnType(tt.sqlType)
			assert.Equal(t, tt.expected, result, "Type mapping mismatch for %s", tt.sqlType)
		})
	}
}

// TestLoadColumns_WithPrimaryKey tests the loading of column information
// including primary key detection
func TestLoadColumns_WithPrimaryKey(t *testing.T) {
	ctx := context.Background()

	// Use in-memory database with a unique connection identifier for this test
	// Generate a random name to avoid file locking issues between tests
	randID := fmt.Sprintf("memory_%d", time.Now().UnixNano())
	cfg := Config{
		ConnString: randID,
	}

	// Verify connection string matches our random name
	connStr := cfg.ConnectionString()
	assert.Equal(t, randID, connStr)

	connector, err := connectors.New("duckdb", cfg)
	require.NoError(t, err)

	// Create test table from SQL file
	db := connector.(*Connector).db

	// Drop the table first if it exists
	_, err = db.Exec("DROP TABLE IF EXISTS test_table")
	require.NoError(t, err)

	sqlSchema, err := os.ReadFile(filepath.Join("testdata", "test_schema.sql"))
	require.NoError(t, err)
	_, err = db.Exec(string(sqlSchema))
	require.NoError(t, err)

	// Test primary key detection
	c := connector.(*Connector)
	columns, err := c.LoadsColumns(ctx, "test_table")
	require.NoError(t, err)

	// Verify results
	assert.Len(t, columns, 3)

	// Find and verify primary key column
	var foundPK bool
	for _, col := range columns {
		if col.Name == "id" {
			assert.True(t, col.PrimaryKey, "Column 'id' should be a primary key")
			foundPK = true
		} else {
			assert.False(t, col.PrimaryKey, "Column '%s' should not be a primary key", col.Name)
		}
	}
	assert.True(t, foundPK, "Primary key column 'id' not found")

	// Clean up
	_, err = db.Exec("DROP TABLE IF EXISTS test_table")
	require.NoError(t, err)

	// Close the connection explicitly
	err = db.Close()
	require.NoError(t, err)
}
