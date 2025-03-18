package postgres

import (
	"crypto/tls"
	"crypto/x509"
	_ "embed"

	"github.com/jackc/pgx/v4"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v3"
)

//go:embed readme.md
var docString string

type Config struct {
	Hosts      []string `yaml:"hosts"`
	Database   string   `yaml:"database"`
	User       string   `yaml:"user"`
	Password   string   `yaml:"password"`
	Port       int      `yaml:"port"`
	TLSFile    string   `yaml:"tls_file"`
	EnableTLS  bool     `yaml:"enable_tls"`
	ConnString string   `yaml:"conn_string"` // Connection string in format: postgresql://user:password@host:port/database
	Schema     string   `yaml:"schema"`      // Database schema name for table access (format: schema.table_name)
	IsReadonly bool     `yaml:"is_readonly"`
}

func (c Config) Readonly() bool {
	return c.IsReadonly
}

func (c Config) ExtraPrompt() []string {
	return []string{}
}

// UnmarshalYAML implements the yaml.Unmarshaler interface to allow for both
// direct connection string or full configuration objects in YAML
func (c *Config) UnmarshalYAML(value *yaml.Node) error {
	// Try to unmarshal as a string (connection string)
	var connString string
	if err := value.Decode(&connString); err == nil && len(connString) > 0 {
		c.ConnString = connString
		return nil
	}

	// If that didn't work, try to unmarshal as a full config object
	type configAlias Config // Use alias to avoid infinite recursion
	var alias configAlias
	if err := value.Decode(&alias); err != nil {
		return err
	}

	*c = Config(alias)
	return nil
}

func (c Config) TLSConfig() (*tls.Config, error) {
	if c.EnableTLS {
		rootCertPool := x509.NewCertPool()
		if len(c.TLSFile) > 0 {
			if ok := rootCertPool.AppendCertsFromPEM([]byte(c.TLSFile)); !ok {
				return nil, errors.New("unable to add TLS to cert pool")
			}
		}
		return &tls.Config{
			RootCAs:    rootCertPool,
			ServerName: c.Hosts[0],

			InsecureSkipVerify: len(c.TLSFile) == 0,
		}, nil
	}

	return nil, nil
}

func (c Config) MakeConfig() (*pgx.ConnConfig, error) {
	// If connection string is provided, use it directly
	if c.ConnString != "" {
		// ParseConfig parses a connection string and returns a *pgx.ConnConfig
		config, err := pgx.ParseConfig(c.ConnString)
		if err != nil {
			return nil, errors.Wrap(err, "unable to parse connection string")
		}

		// Apply TLS settings if EnableTLS is true
		if c.EnableTLS {
			tlsConfig, err := c.TLSConfig()
			if err != nil {
				return nil, err
			}
			config.TLSConfig = tlsConfig
		}

		config.PreferSimpleProtocol = true
		return config, nil
	}

	// Otherwise, use the individual fields as before
	tlsConfig, err := c.TLSConfig()
	if err != nil {
		return nil, err
	}

	config, _ := pgx.ParseConfig("")
	config.Host = c.Hosts[0]
	config.Port = uint16(c.Port)
	config.Database = c.Database
	config.User = c.User
	config.Password = string(c.Password)
	config.TLSConfig = tlsConfig
	config.PreferSimpleProtocol = true

	return config, nil
}

func (c Config) Type() string {
	return "postgres"
}

func (c Config) Doc() string {
	return docString
}
