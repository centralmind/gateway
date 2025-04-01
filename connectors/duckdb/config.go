package duckdb

import (
	_ "embed"
	"fmt"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

//go:embed readme.md
var docString string

// Config represents the configuration for a DuckDB connection
type Config struct {
	Hosts      []string `json:"hosts" yaml:"hosts"`             // List of database file paths
	Database   string   `json:"database" yaml:"database"`       // Database file name
	ReadOnly   bool     `json:"read_only" yaml:"read_only"`     // Whether to open database in read-only mode
	Memory     bool     `json:"memory" yaml:"memory"`           // Whether to create an in-memory database
	ConnString string   `json:"conn_string" yaml:"conn_string"` // Direct connection string
	InitSQL    string   `json:"init_sql" yaml:"init_sql"`       // SQL commands to execute on connection initialization
}

func (c Config) Readonly() bool {
	return false
}

// UnmarshalYAML implements the yaml.Unmarshaler interface
func (c *Config) UnmarshalYAML(value *yaml.Node) error {
	// Try to unmarshal as a string (connection string)
	var connString string
	if err := value.Decode(&connString); err == nil && len(connString) > 0 {
		c.ConnString = connString
		return nil
	}

	// If that didn't work, try to unmarshal as a full config object
	type configAlias Config
	var alias configAlias
	if err := value.Decode(&alias); err != nil {
		return err
	}

	*c = Config(alias)
	return nil
}

// ConnectionString generates a connection string for DuckDB
func (c Config) ConnectionString() string {
	// If direct connection string is provided, use it
	if c.ConnString != "" {
		return c.ConnString
	}

	// For in-memory database
	if c.Memory {
		return ":memory:"
	}

	// For file-based database
	dbPath := ""
	if len(c.Hosts) > 0 && c.Database != "" {
		// Combine the first host (path) with database name
		dbPath = filepath.Join(c.Hosts[0], c.Database)
	} else if len(c.Hosts) > 0 {
		// Use the first host as the full path
		dbPath = c.Hosts[0]
	} else if c.Database != "" {
		// Use just the database name as path
		dbPath = c.Database
	}

	return dbPath
}

// Validate checks if the configuration is valid
func (c Config) Validate() error {
	if !c.Memory && len(c.Hosts) == 0 && c.Database == "" {
		return fmt.Errorf("either hosts/database path or memory mode must be specified")
	}
	return nil
}

// Type returns the type of the connector
func (c Config) Type() string {
	return "duckdb"
}

// Doc returns documentation about the configuration
func (c Config) Doc() string {
	return docString
}

// ExtraPrompt returns additional prompt information for the configuration
func (c Config) ExtraPrompt() []string {
	return []string{
		"Use symbol ':' instead of '@' for named parameters in sql query",
	}
}
