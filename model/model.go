package model

import (
	"encoding/json"
	"os"
	"strings"

	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"
)

// ColumnType represents the allowed data types for columns
type ColumnType string

const (
	TypeString   ColumnType = "string"
	TypeDatetime ColumnType = "date-time"
	TypeNumber   ColumnType = "number"
	TypeInteger  ColumnType = "integer"
	TypeBoolean  ColumnType = "boolean"
	TypeNull     ColumnType = "null"
	TypeObject   ColumnType = "object"
	TypeArray    ColumnType = "array"
)

// IsValid checks if the column type is one of the allowed types
func (ct ColumnType) IsValid() bool {
	switch ct {
	case TypeString, TypeNumber, TypeInteger, TypeBoolean, TypeNull, TypeObject, TypeArray, TypeDatetime:
		return true
	default:
		return false
	}
}

// String implements fmt.Stringer interface
func (ct ColumnType) String() string {
	return string(ct)
}

// MarshalYAML implements yaml.Marshaler interface
func (ct ColumnType) MarshalYAML() (interface{}, error) {
	return ct.String(), nil
}

// UnmarshalYAML implements yaml.Unmarshaler interface
func (ct *ColumnType) UnmarshalYAML(value *yaml.Node) error {
	var str string
	if err := value.Decode(&str); err != nil {
		return err
	}
	*ct = ColumnType(str)
	if !ct.IsValid() {
		return xerrors.Errorf("invalid column type: %s", str)
	}
	return nil
}

// MarshalJSON implements json.Marshaler interface
func (ct ColumnType) MarshalJSON() ([]byte, error) {
	return json.Marshal(ct.String())
}

// UnmarshalJSON implements json.Unmarshaler interface
func (ct *ColumnType) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	*ct = ColumnType(str)
	if !ct.IsValid() {
		return xerrors.Errorf("invalid column type: %s", str)
	}
	return nil
}

type Config struct {
	API      APIParams      `yaml:"api" json:"api"`
	Database Database       `yaml:"database" json:"database"`
	Plugins  map[string]any `yaml:"plugins" json:"plugins"`
}

func FromYaml(raw []byte) (*Config, error) {
	// Parse YAML and expand environment variables before unmarshaling to final config
	var node yaml.Node
	err := yaml.Unmarshal(raw, &node)
	if err != nil {
		return nil, xerrors.Errorf("unable to parse yaml: %w", err)
	}

	// Expand environment variables in the node
	expandEnvIfNotQuoted(&node)

	// Unmarshal the processed YAML to the Config struct
	var gw Config
	if err := node.Decode(&gw); err != nil {
		return nil, xerrors.Errorf("unable to decode yaml: %w", err)
	}

	// Process any additional string fields that might need environment variable expansion
	// This handles cases like SQL strings that might be quoted in the YAML
	// but still need environment variable expansion
	expandEnvInConfig(&gw)

	return &gw, nil
}

// expandEnvIfNotQuoted expands environment variables in a YAML node
func expandEnvIfNotQuoted(node *yaml.Node) {
	if node.Kind == yaml.ScalarNode {
		value := node.Value
		// Check if the value is quoted (starts and ends with quotes)
		isQuoted := (strings.HasPrefix(value, "'") && strings.HasSuffix(value, "'")) ||
			(strings.HasPrefix(value, "\"") && strings.HasSuffix(value, "\""))

		if !isQuoted {
			node.Value = os.ExpandEnv(value)
		}
	} else if node.Kind == yaml.MappingNode {
		// Process mapping (key-value pairs)
		for i := 0; i < len(node.Content); i += 2 {
			expandEnvIfNotQuoted(node.Content[i+1]) // Process only values, skip keys
		}
	} else if node.Kind == yaml.SequenceNode {
		// Process sequences (arrays)
		for _, item := range node.Content {
			expandEnvIfNotQuoted(item)
		}
	}
}

// expandEnvInConfig recursively processes a configuration to expand environment variables
// in all string fields, including map values and nested configurations
func expandEnvInConfig(cfg *Config) {
	// Process database connection
	cfg.Database.Connection = processAnyField(cfg.Database.Connection)

	// Process plugins configs
	for k, v := range cfg.Plugins {
		cfg.Plugins[k] = processAnyField(v)
	}
}

// processAnyField recursively processes any field, expanding environment variables in strings
func processAnyField(v interface{}) interface{} {
	if v == nil {
		return nil
	}

	switch val := v.(type) {
	case string:
		// Process string value
		return os.ExpandEnv(val)
	case map[string]interface{}:
		// Process map values
		for k, mv := range val {
			val[k] = processAnyField(mv)
		}
		return val
	case []interface{}:
		// Process slice values
		for i, sv := range val {
			val[i] = processAnyField(sv)
		}
		return val
	case map[interface{}]interface{}:
		// Process map with interface keys (sometimes happens with YAML)
		result := make(map[string]interface{})
		for k, mv := range val {
			if kStr, ok := k.(string); ok {
				result[kStr] = processAnyField(mv)
			}
		}
		return result
	default:
		// Other types are returned as is
		return val
	}
}

func (g *Config) ParamRaw() string {
	switch p := g.Database.Connection.(type) {
	case []byte:
		return string(p)
	case string:
		return p
	default:
		data, _ := json.Marshal(p)
		return string(data)
	}
}

type APIParams struct {
	Name        string `yaml:"name" json:"name,omitempty"`
	Description string `yaml:"description" json:"description,omitempty"`
	Version     string `yaml:"version" json:"version,omitempty"`
}

type Database struct {
	Type       string               `yaml:"type" json:"type,omitempty"`
	Connection any                  `yaml:"connection" json:"connection,omitempty"`
	Endpoints  []Endpoint           `yaml:"endpoints" json:"endpoints,omitempty"`
	Tables     []TableWithEndpoints `yaml:"tables" json:"tables,omitempty"`
}

// GetAllEndpoints returns all endpoints from both database level and table level
func (d Database) GetAllEndpoints() []Endpoint {
	allEndpoints := make([]Endpoint, 0, len(d.Endpoints))
	
	// Add database-level endpoints
	allEndpoints = append(allEndpoints, d.Endpoints...)
	
	// Add table-level endpoints
	for _, table := range d.Tables {
		allEndpoints = append(allEndpoints, table.Endpoints...)
	}
	
	return allEndpoints
}

type Table struct {
	Name     string         `yaml:"name" json:"name,omitempty"`
	Columns  []ColumnSchema `yaml:"columns" json:"columns,omitempty"`
	RowCount int            `yaml:"row_count" json:"row_count,omitempty"`
}

type TableWithEndpoints struct {
	Name      string         `yaml:"name" json:"name,omitempty"`
	Columns   []ColumnSchema `yaml:"columns" json:"columns,omitempty"`
	RowCount  int            `yaml:"row_count" json:"row_count,omitempty"`
	Endpoints []Endpoint     `yaml:"endpoints" json:"endpoints,omitempty"`
}

type ColumnSchema struct {
	Name       string     `yaml:"name" json:"name,omitempty"`
	Type       ColumnType `yaml:"type" json:"type,omitempty"`
	PrimaryKey bool       `yaml:"primary_key" json:"primary_key,omitempty"`
	PII        bool       `yaml:"pii" json:"pii,omitempty"`
}

type Endpoint struct {
	Group         string           `yaml:"group" json:"group,omitempty"`
	HTTPMethod    string           `yaml:"http_method" json:"http_method,omitempty"`
	HTTPPath      string           `yaml:"http_path" json:"path,omitempty"`
	MCPMethod     string           `yaml:"mcp_method" json:"mcp_method,omitempty"`
	Summary       string           `yaml:"summary" json:"summary,omitempty"`
	Description   string           `yaml:"description" json:"description,omitempty"`
	Query         string           `yaml:"query" json:"query,omitempty"`
	IsArrayResult bool             `yaml:"is_array_result" json:"is_array_result,omitempty"`
	Params        []EndpointParams `yaml:"params" json:"params,omitempty"`
}

type EndpointParams struct {
	Name     string      `yaml:"name" json:"name,omitempty"`
	Type     string      `yaml:"type" json:"type,omitempty"`
	Location string      `yaml:"location" json:"location,omitempty"`
	Required bool        `yaml:"required" json:"required,omitempty"`
	Format   string      `yaml:"format,omitempty" json:"format,omitempty"`
	Default  interface{} `yaml:"default,omitempty" json:"default,omitempty"`
}

func FromDSN(dsn string) (*Config, error) {
	// Expand environment variables in DSN string
	expandedDSN := os.ExpandEnv(dsn)

	// Extract database type from DSN (assuming format like "postgres://..." or "mysql://...")
	dbType := ""
	if idx := strings.Index(expandedDSN, "://"); idx != -1 {
		dbType = expandedDSN[:idx]
	}

	return &Config{
		API: APIParams{
			Name:        "Auto API",
			Description: "Direct database connection API",
			Version:     "1.0",
		},
		Database: Database{
			Type:       dbType,
			Connection: expandedDSN,
		},
	}, nil
}
