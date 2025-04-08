package sqlite

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/centralmind/gateway/connectors"
	"github.com/centralmind/gateway/model"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConnector(t *testing.T) {
	ctx := context.Background()

	// Create a temporary directory for the test database
	tmpDir, err := os.MkdirTemp("", "sqlite-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test.db")
	logrus.Infof("SQLite database path: %s", dbPath)

	cfg := Config{
		Hosts:    []string{tmpDir},
		Database: "test.db",
	}

	connector, err := connectors.New("sqlite", cfg)
	assert.NoError(t, err)
	assert.NotNil(t, connector)

	// Create test tables and insert data from SQL file
	db := connector.(*Connector).db
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
		assert.NoError(t, err)
		assert.Len(t, tables, 2)

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
		assert.Equal(t, int64(3), rows[0]["total_count"])
	})

	t.Run("Query Endpoint with Parameters", func(t *testing.T) {
		endpoint := model.Endpoint{
			Query: `SELECT name, age, email 
					FROM users 
					WHERE age > :min_age 
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
		assert.NoError(t, err)
		assert.Len(t, rows, 2)

		// Verify results
		expected := []map[string]any{
			{"name": "Bob Johnson", "age": int64(35), "email": "bob@example.com"},
			{"name": "John Doe", "age": int64(30), "email": "john@example.com"},
		}

		assert.Equal(t, len(expected), len(rows))
		for i, exp := range expected {
			assert.Equal(t, exp["name"], rows[i]["name"])
			assert.Equal(t, exp["age"], rows[i]["age"])
			assert.Equal(t, exp["email"], rows[i]["email"])
		}
	})
}

func TestSQLiteTypeMapping(t *testing.T) {
	c := &Connector{}

	tests := []struct {
		name     string
		sqlType  string
		expected model.ColumnType
	}{
		// String types
		{"text", "TEXT", model.TypeString},
		{"varchar", "VARCHAR", model.TypeString},
		{"char", "CHAR", model.TypeString},
		{"clob", "CLOB", model.TypeString},

		// Numeric types
		{"real", "REAL", model.TypeNumber},
		{"float", "FLOAT", model.TypeNumber},
		{"double", "DOUBLE", model.TypeNumber},

		// Integer types
		{"integer", "INTEGER", model.TypeInteger},
		{"int", "INT", model.TypeInteger},
		{"bigint", "BIGINT", model.TypeInteger},
		{"smallint", "SMALLINT", model.TypeInteger},
		{"tinyint", "TINYINT", model.TypeInteger},

		// Boolean type
		{"boolean", "BOOLEAN", model.TypeBoolean},

		// Date/Time types
		{"datetime", "DATETIME", model.TypeDatetime},
		{"date", "DATE", model.TypeDatetime},
		{"time", "TIME", model.TypeDatetime},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := c.GuessColumnType(tt.sqlType)
			assert.Equal(t, tt.expected, result, "Type mapping mismatch for %s", tt.sqlType)
		})
	}
}

func TestLoadColumns_WithPrimaryKey(t *testing.T) {
	ctx := context.Background()

	// Create a temporary directory for the test database
	tmpDir, err := os.MkdirTemp("", "sqlite-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	cfg := Config{
		Hosts:    []string{tmpDir},
		Database: "test.db",
	}

	connector, err := connectors.New("sqlite", cfg)
	require.NoError(t, err)

	// Create test table from SQL file
	db := connector.(*Connector).db
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
}
