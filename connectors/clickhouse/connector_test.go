package clickhouse

import (
	"context"
	_ "embed"
	"path/filepath"
	"testing"

	"github.com/centralmind/gateway/connectors"
	"github.com/centralmind/gateway/model"
	"github.com/docker/go-connections/nat"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/clickhouse"
)

func TestConnector(t *testing.T) {
	ctx := context.Background()
	user := "clickhouse"
	password := "password"
	dbname := "testdb"
	clickHouseContainer, err := clickhouse.Run(ctx,
		"clickhouse/clickhouse-server:23.3.8.21-alpine",
		clickhouse.WithUsername(user),
		clickhouse.WithPassword(password),
		clickhouse.WithDatabase(dbname),
		clickhouse.WithInitScripts(filepath.Join("testdata", "test_data.sql")),
	)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, testcontainers.TerminateContainer(clickHouseContainer))
	}()

	connStr, err := clickHouseContainer.ConnectionString(ctx)
	require.NoError(t, err)
	logrus.Infof("conn string: %s", connStr)
	host, err := clickHouseContainer.Host(ctx)
	require.NoError(t, err)
	port, err := clickHouseContainer.MappedPort(ctx, nat.Port("8123/tcp"))
	require.NoError(t, err)
	cfg := Config{
		Host:     host,
		Database: dbname,
		User:     user,
		Password: password,
		Port:     port.Int(),
		Secure:   false,
	}
	connector, err := connectors.New("clickhouse", cfg)
	assert.NoError(t, err)
	assert.NotNil(t, connector)

	t.Run("Ping Database", func(t *testing.T) {
		err := connector.Ping(ctx)
		assert.NoError(t, err)
	})

	t.Run("Discovery Tables", func(t *testing.T) {
		tables, err := connector.Discovery(ctx, nil)
		assert.NoError(t, err)
		assert.NotEmpty(t, tables)
	})

	t.Run("Read Endpoint", func(t *testing.T) {
		endpoint := model.Endpoint{
			Query:  "SELECT COUNT(*) AS total_count FROM gachi_teams",
			Params: []model.EndpointParams{},
		}
		params := map[string]any{}
		rows, err := connector.Query(ctx, endpoint, params)
		assert.NoError(t, err)
		assert.NotEmpty(t, rows)
	})

	t.Run("Query Endpoint", func(t *testing.T) {
		endpoint := model.Endpoint{
			Query: `SELECT name, strength_level, special_move 
					FROM gachi_personas 
					WHERE strength_level >= :min_strength 
					ORDER BY strength_level DESC`,
			Params: []model.EndpointParams{
				{
					Name:     "min_strength",
					Type:     "int",
					Required: true,
				},
			},
		}
		params := map[string]any{
			"min_strength": 95,
		}
		rows, err := connector.Query(ctx, endpoint, params)
		assert.NoError(t, err)
		assert.NotEmpty(t, rows)

		// Verify results
		expected := []map[string]any{
			{"name": "Billy Herrington", "strength_level": int32(100), "special_move": "Anvil Drop"},
			{"name": "Van Darkholme", "strength_level": int32(95), "special_move": "Whip of Submission"},
		}

		assert.Equal(t, len(expected), len(rows))
		for i, exp := range expected {
			assert.Equal(t, exp["name"], rows[i]["name"])
			assert.Equal(t, exp["strength_level"], rows[i]["strength_level"])
			assert.Equal(t, exp["special_move"], rows[i]["special_move"])
		}
	})
}

func TestClickHouseTypeMapping(t *testing.T) {
	c := &Connector{}

	tests := []struct {
		name     string
		sqlType  string
		expected model.ColumnType
	}{
		// String types
		{"String", "String", model.TypeString},
		{"FixedString", "FixedString(16)", model.TypeString},
		{"UUID", "UUID", model.TypeString},
		{"IPv4", "IPv4", model.TypeString},
		{"IPv6", "IPv6", model.TypeString},
		{"Enum8", "Enum8", model.TypeString},
		{"Enum16", "Enum16", model.TypeString},

		// Numeric types
		{"Float32", "Float32", model.TypeNumber},
		{"Float64", "Float64", model.TypeNumber},
		{"Decimal", "Decimal(10,2)", model.TypeNumber},
		{"Decimal32", "Decimal32(4)", model.TypeNumber},
		{"Decimal64", "Decimal64(4)", model.TypeNumber},
		{"Decimal128", "Decimal128(4)", model.TypeNumber},

		// Integer types
		{"Int8", "Int8", model.TypeInteger},
		{"Int16", "Int16", model.TypeInteger},
		{"Int32", "Int32", model.TypeInteger},
		{"Int64", "Int64", model.TypeInteger},
		{"UInt8", "UInt8", model.TypeInteger},
		{"UInt16", "UInt16", model.TypeInteger},
		{"UInt32", "UInt32", model.TypeInteger},
		{"UInt64", "UInt64", model.TypeInteger},

		// Boolean type
		{"Bool", "Bool", model.TypeBoolean},

		// Object types
		{"JSON", "JSON", model.TypeObject},
		{"Object", "Object('json')", model.TypeObject},

		// Array types
		{"Array", "Array(String)", model.TypeArray},
		{"Nested", "Nested(x String, y Int32)", model.TypeArray},
		{"Tuple", "Tuple(String, Int32)", model.TypeArray},

		// Date/Time types
		{"Date", "Date", model.TypeDatetime},
		{"DateTime", "DateTime", model.TypeDatetime},
		{"DateTime64", "DateTime64(3)", model.TypeDatetime},
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

	user := "clickhouse"
	password := "password"
	dbname := "testdb"

	clickHouseContainer, err := clickhouse.Run(ctx,
		"clickhouse/clickhouse-server:23.3.8.21-alpine",
		clickhouse.WithUsername(user),
		clickhouse.WithPassword(password),
		clickhouse.WithDatabase(dbname),
		clickhouse.WithInitScripts(filepath.Join("testdata", "test_schema.sql")),
	)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, testcontainers.TerminateContainer(clickHouseContainer))
	}()

	host, err := clickHouseContainer.Host(ctx)
	require.NoError(t, err)
	port, err := clickHouseContainer.MappedPort(ctx, nat.Port("8123/tcp"))
	require.NoError(t, err)

	cfg := Config{
		Host:     host,
		Database: dbname,
		User:     user,
		Password: password,
		Port:     port.Int(),
		Secure:   false,
	}

	connector, err := connectors.New("clickhouse", cfg)
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
