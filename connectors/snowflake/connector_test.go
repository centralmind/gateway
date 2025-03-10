package snowflake

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/centralmind/gateway/model"
)

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
