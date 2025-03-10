package bigquery

import (
	"testing"

	"github.com/centralmind/gateway/model"
	"github.com/stretchr/testify/assert"
)

func TestConfig_Type(t *testing.T) {
	cfg := Config{}
	assert.Equal(t, "bigquery", cfg.Type())
}

func TestConfig_Doc(t *testing.T) {
	cfg := Config{}
	assert.NotEmpty(t, cfg.Doc())
}

func TestConnector_GuessColumnType(t *testing.T) {
	c := &Connector{}
	tests := []struct {
		name     string
		sqlType  string
		expected model.ColumnType
	}{
		{"string", "STRING", model.TypeString},
		{"integer", "INTEGER", model.TypeInteger},
		{"float", "FLOAT64", model.TypeNumber},
		{"boolean", "BOOLEAN", model.TypeBoolean},
		{"timestamp", "TIMESTAMP", model.TypeDatetime},
		{"record", "RECORD", model.TypeObject},
		{"array", "ARRAY", model.TypeArray},
		{"unknown", "UNKNOWN_TYPE", model.TypeString},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := c.GuessColumnType(tt.sqlType)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Note: Integration tests would require actual BigQuery credentials and connection
// They should be implemented separately and run in a controlled environment
func TestConnector_Integration_Disabled(t *testing.T) {
	t.Skip("Integration tests are disabled")
}
