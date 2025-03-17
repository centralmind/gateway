package model

import (
	"encoding/json"

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
	var gw Config
	err := yaml.Unmarshal(raw, &gw)
	if err != nil {
		return nil, xerrors.Errorf("unable to parse yaml: %w", err)
	}
	return &gw, nil
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
	Type       string     `yaml:"type" json:"type,omitempty"`
	Connection any        `yaml:"connection" json:"connection,omitempty"`
	Endpoints  []Endpoint `yaml:"endpoints" json:"endpoints,omitempty"`
}

type Table struct {
	Name     string         `yaml:"name" json:"name,omitempty"`
	Columns  []ColumnSchema `yaml:"columns" json:"columns,omitempty"`
	RowCount int            `yaml:"row_count" json:"row_count,omitempty"`
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
