package postgres

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/centralmind/gateway/connectors"
	"github.com/centralmind/gateway/model"
	"github.com/docker/go-connections/nat"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestConnector(t *testing.T) {
	ctx := context.Background()

	dbName := "users"
	dbUser := "user"
	dbPassword := "password"

	postgresContainer, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithInitScripts(filepath.Join("testdata", "test_data.sql")),
		postgres.WithDatabase(dbName),
		postgres.WithUsername(dbUser),
		postgres.WithPassword(dbPassword),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(5*time.Second)),
	)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, testcontainers.TerminateContainer(postgresContainer))
	}()

	connStr, err := postgresContainer.ConnectionString(ctx)
	require.NoError(t, err)
	logrus.Infof("conn string: %s", connStr)
	host, err := postgresContainer.Host(ctx)
	require.NoError(t, err)
	port, err := postgresContainer.MappedPort(ctx, nat.Port("5432/tcp"))
	require.NoError(t, err)
	cfg := Config{
		Hosts:    []string{host},
		Database: dbName,
		User:     dbUser,
		Password: dbPassword,
		Port:     port.Int(),
		Schema:   "public",
	}
	connector, err := connectors.New("postgres", cfg)
	assert.NoError(t, err)
	assert.NotNil(t, connector)

	t.Run("Ping Database", func(t *testing.T) {
		err := connector.Ping(ctx)
		assert.NoError(t, err)
	})

	t.Run("Discovery Tables", func(t *testing.T) {
		tables, err := connector.Discovery(ctx)
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
			Query: `SELECT name, strength_level, special_move, team_id 
					FROM gachi_personas 
					WHERE team_id = :team_id 
					ORDER BY strength_level DESC`,
			Params: []model.EndpointParams{
				{
					Name:     "team_id",
					Type:     "int",
					Required: true,
				},
			},
		}
		params := map[string]any{
			"team_id": 2,
		}
		rows, err := connector.Query(ctx, endpoint, params)
		assert.NoError(t, err)
		assert.NotEmpty(t, rows)

		// Verify results
		expected := []map[string]any{
			{"name": "Billy Herrington", "strength_level": int64(100), "special_move": "Anvil Drop", "team_id": int64(2)},
			{"name": "Hard Rod", "strength_level": int64(88), "special_move": "Steel Pipe Crush", "team_id": int64(2)},
			{"name": "Mark Wolff", "strength_level": int64(85), "special_move": "Wolf Howl Slam", "team_id": int64(2)},
			{"name": "Muscle Daddy", "strength_level": int64(79), "special_move": "Bear Hug Crush", "team_id": int64(2)},
		}

		assert.Equal(t, len(expected), len(rows))
		for i, exp := range expected {
			assert.Equal(t, exp["name"], rows[i]["name"])
			assert.Equal(t, exp["strength_level"], rows[i]["strength_level"])
			assert.Equal(t, exp["special_move"], rows[i]["special_move"])
			assert.Equal(t, exp["team_id"], rows[i]["team_id"])
		}
	})
}

func TestPostgresTypeMapping(t *testing.T) {
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
		{"name", "NAME", model.TypeString},
		{"bpchar", "BPCHAR", model.TypeString},
		{"bytea", "BYTEA", model.TypeString},
		{"uuid", "UUID", model.TypeString},
		{"xml", "XML", model.TypeString},
		{"citext", "CITEXT", model.TypeString},
		{"character", "CHARACTER", model.TypeString},
		{"character varying", "CHARACTER VARYING", model.TypeString},
		{"nchar", "NCHAR", model.TypeString},
		{"nvarchar", "NVARCHAR", model.TypeString},

		// Numeric types
		{"decimal", "DECIMAL", model.TypeNumber},
		{"numeric", "NUMERIC", model.TypeNumber},
		{"real", "REAL", model.TypeNumber},
		{"double precision", "DOUBLE PRECISION", model.TypeNumber},
		{"money", "MONEY", model.TypeNumber},

		// Integer types
		{"int4", "INT4", model.TypeInteger},
		{"int8", "INT8", model.TypeInteger},
		{"smallint", "SMALLINT", model.TypeInteger},
		{"integer", "INTEGER", model.TypeInteger},
		{"bigint", "BIGINT", model.TypeInteger},
		{"smallserial", "SMALLSERIAL", model.TypeInteger},
		{"serial", "SERIAL", model.TypeInteger},
		{"bigserial", "BIGSERIAL", model.TypeInteger},

		// Boolean type
		{"boolean", "BOOLEAN", model.TypeBoolean},
		{"bool", "BOOL", model.TypeBoolean},

		// Array types
		{"array", "TEXT[]", model.TypeArray},
		{"array2", "INTEGER[]", model.TypeArray},

		// JSON types
		{"json", "JSON", model.TypeObject},
		{"jsonb", "JSONB", model.TypeObject},

		// Date/Time types
		{"date", "DATE", model.TypeDatetime},
		{"time", "TIME", model.TypeDatetime},
		{"timetz", "TIMETZ", model.TypeDatetime},
		{"timestamp", "TIMESTAMP", model.TypeDatetime},
		{"timestamptz", "TIMESTAMPTZ", model.TypeDatetime},
		{"interval", "INTERVAL", model.TypeDatetime},
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

	dbName := "testdb"
	dbUser := "postgres"
	dbPassword := "password"

	postgresContainer, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithInitScripts(filepath.Join("testdata", "test_schema.sql")),
		postgres.WithDatabase(dbName),
		postgres.WithUsername(dbUser),
		postgres.WithPassword(dbPassword),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(5*time.Second)),
	)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, testcontainers.TerminateContainer(postgresContainer))
	}()

	host, err := postgresContainer.Host(ctx)
	require.NoError(t, err)
	port, err := postgresContainer.MappedPort(ctx, nat.Port("5432/tcp"))
	require.NoError(t, err)

	cfg := Config{
		Hosts:    []string{host},
		Database: dbName,
		User:     dbUser,
		Password: dbPassword,
		Port:     port.Int(),
		Schema:   "public",
	}

	connector, err := connectors.New("postgres", cfg)
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
