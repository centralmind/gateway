package snowflake

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/centralmind/gateway/model"
)

func TestParseConnectionString(t *testing.T) {
	tests := []struct {
		name        string
		connString  string
		expected    Config
		shouldError bool
	}{
		{
			name:       "full connection string",
			connString: "snowflake://user1:password12@XXXXXXX-XXX5684/MY_COPY_DB/PUBLIC?warehouse=COMPUTE_WH&role=MYROLE",
			expected: Config{
				User:       "user1",
				Password:   "password12",
				Account:    "XXXXXXX-XXX5684",
				Database:   "MY_COPY_DB",
				Schema:     "PUBLIC",
				Warehouse:  "COMPUTE_WH",
				Role:       "MYROLE",
				ConnString: "snowflake://user1:password12@XXXXXXX-XXX5684/MY_COPY_DB/PUBLIC?warehouse=COMPUTE_WH&role=MYROLE",
			},
			shouldError: false,
		},
		{
			name:       "connection string without snowflake prefix",
			connString: "user1:password12@XXXXXXX-XXX5684/MY_COPY_DB/PUBLIC?warehouse=COMPUTE_WH&role=MYROLE",
			expected: Config{
				User:       "user1",
				Password:   "password12",
				Account:    "XXXXXXX-XXX5684",
				Database:   "MY_COPY_DB",
				Schema:     "PUBLIC",
				Warehouse:  "COMPUTE_WH",
				Role:       "MYROLE",
				ConnString: "snowflake://user1:password12@XXXXXXX-XXX5684/MY_COPY_DB/PUBLIC?warehouse=COMPUTE_WH&role=MYROLE",
			},
			shouldError: false,
		},
		{
			name:       "connection string with only database",
			connString: "snowflake://user:pass@account/database",
			expected: Config{
				User:       "user",
				Password:   "pass",
				Account:    "account",
				Database:   "database",
				ConnString: "snowflake://user:pass@account/database",
			},
			shouldError: false,
		},
		{
			name:       "empty connection string",
			connString: "",
			expected: Config{
				ConnString: "",
			},
			shouldError: false,
		},
		{
			name:       "preserves existing fields",
			connString: "snowflake://user:pass@account/database/schema",
			expected: Config{
				User:       "existing_user", // Should not be overwritten
				Password:   "pass",
				Account:    "account",
				Database:   "database",
				Schema:     "schema",
				ConnString: "snowflake://user:pass@account/database/schema",
			},
			shouldError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := Config{
				ConnString: tt.connString,
			}

			// For the "preserves existing fields" test, set existing user
			if tt.name == "preserves existing fields" {
				config.User = "existing_user"
			}

			err := config.parseConnectionString()

			if tt.shouldError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)

			// For the "preserves existing fields" test, we expect the user to remain unchanged
			if tt.name == "preserves existing fields" {
				assert.Equal(t, "existing_user", config.User)
				assert.Equal(t, tt.expected.Password, config.Password)
				assert.Equal(t, tt.expected.Account, config.Account)
				assert.Equal(t, tt.expected.Database, config.Database)
				assert.Equal(t, tt.expected.Schema, config.Schema)
				return
			}

			assert.Equal(t, tt.expected.User, config.User)
			assert.Equal(t, tt.expected.Password, config.Password)
			assert.Equal(t, tt.expected.Account, config.Account)
			assert.Equal(t, tt.expected.Database, config.Database)
			assert.Equal(t, tt.expected.Schema, config.Schema)
			assert.Equal(t, tt.expected.Warehouse, config.Warehouse)
			assert.Equal(t, tt.expected.Role, config.Role)
		})
	}
}

func TestSnowflakeTypeMapping(t *testing.T) {
	c := &Connector{}

	tests := []struct {
		name     string
		sqlType  string
		expected model.ColumnType
	}{
		// String types
		{"string", "STRING", model.TypeString},
		{"text", "TEXT", model.TypeString},
		{"varchar", "VARCHAR", model.TypeString},
		{"char", "CHAR", model.TypeString},
		{"binary", "BINARY", model.TypeString},
		{"varbinary", "VARBINARY", model.TypeString},

		// Numeric types
		{"number", "NUMBER", model.TypeNumber},
		{"decimal", "DECIMAL", model.TypeNumber},
		{"numeric", "NUMERIC", model.TypeNumber},
		{"float", "FLOAT", model.TypeNumber},
		{"double", "DOUBLE", model.TypeNumber},

		// Integer types
		{"int", "INT", model.TypeInteger},
		{"integer", "INTEGER", model.TypeInteger},
		{"bigint", "BIGINT", model.TypeInteger},
		{"smallint", "SMALLINT", model.TypeInteger},
		{"tinyint", "TINYINT", model.TypeInteger},

		// Boolean type
		{"boolean", "BOOLEAN", model.TypeBoolean},

		// Object types
		{"object", "OBJECT", model.TypeObject},
		{"variant", "VARIANT", model.TypeObject},

		// Array type
		{"array", "ARRAY", model.TypeArray},

		// Date/Time types
		{"date", "DATE", model.TypeDatetime},
		{"time", "TIME", model.TypeDatetime},
		{"timestamp", "TIMESTAMP", model.TypeDatetime},
		{"timestamp_ltz", "TIMESTAMP_LTZ", model.TypeDatetime},
		{"timestamp_ntz", "TIMESTAMP_NTZ", model.TypeDatetime},
		{"timestamp_tz", "TIMESTAMP_TZ", model.TypeDatetime},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := c.GuessColumnType(tt.sqlType)
			assert.Equal(t, tt.expected, result, "Type mapping mismatch for %s", tt.sqlType)
		})
	}
}
