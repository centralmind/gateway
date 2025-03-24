package mongodb

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"go.mongodb.org/mongo-driver/mongo/options"
	"gopkg.in/yaml.v3"
)

//go:embed config.yaml
var docString string

type Config struct {
	Hosts      []string `yaml:"hosts"`
	Database   string   `yaml:"database"`
	Username   string   `yaml:"username"`
	Password   string   `yaml:"password"`
	IsReadonly bool     `yaml:"is_readonly"`
}

func (c Config) Readonly() bool {
	return c.IsReadonly
}

func (c Config) ExtraPrompt() []string {
	return []string{
		"Database: MongoDB (NoSQL database).",
		"Queries must use MongoDB Query Language.",
		"Paginate with 'skip' and 'limit' instead of 'offset' and 'limit'.",
	}
}

func (c Config) Type() string {
	return "mongodb"
}

func (c Config) Doc() string {
	return "MongoDB is a NoSQL database that uses JSON-like documents with optional schemas."
}

func (c Config) ConnectionString() string {
	// URL encode username and password
	encodedUsername := url.QueryEscape(c.Username)
	encodedPassword := url.QueryEscape(c.Password)
	return fmt.Sprintf("mongodb://%s:%s@%s/%s", encodedUsername, encodedPassword, strings.Join(c.Hosts, ","), c.Database)
}

func (c Config) Validate() error {
	if len(c.Hosts) == 0 {
		return fmt.Errorf("hosts are required")
	}

	for _, host := range c.Hosts {
		if !strings.Contains(host, ":") {
			return fmt.Errorf("invalid host format: %s, expected host:port", host)
		}
		parts := strings.Split(host, ":")
		if len(parts) != 2 {
			return fmt.Errorf("invalid host format: %s", host)
		}
		port := parts[1]
		if _, err := strconv.Atoi(port); err != nil {
			return fmt.Errorf("invalid port number: %s", port)
		}
	}

	if c.Database == "" {
		return fmt.Errorf("database is required")
	}

	// Validate database name format
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(c.Database) {
		return fmt.Errorf("invalid database name format")
	}

	if c.Username == "" {
		return fmt.Errorf("username is required")
	}

	if c.Password == "" {
		return fmt.Errorf("password is required")
	}
	return nil
}

func (c *Config) UnmarshalYAML(value *yaml.Node) error {
	// Try to unmarshal as a string (connection string)
	var connString string
	if err := value.Decode(&connString); err == nil {
		// If it's a valid connection string, extract components
		mongoConfig, err := parseMongoDbConnString(connString)
		if err != nil {
			return err
		}

		c.Hosts = mongoConfig.Hosts
		c.Database = mongoConfig.Database
		c.Username = mongoConfig.Username
		c.Password = mongoConfig.Password
		return nil
	}

	// If not a string, attempt to parse as a full configuration object
	type configAlias Config // Use alias to avoid infinite recursion
	var alias configAlias
	if err := value.Decode(&alias); err != nil {
		return errors.Wrap(err, "failed to unmarshal YAML into Config")
	}

	// Copy parsed fields into the original struct
	*c = Config(alias)
	return nil
}

func parseMongoDbConnString(connString string) (*Config, error) {
	// Parse the connection string using MongoDB driver
	opts := options.Client().ApplyURI(connString)
	if opts == nil {
		return nil, fmt.Errorf("failed to parse MongoDB connection string")
	}

	// Extract components from parsed options
	config := &Config{
		Hosts:    opts.Hosts,
		Username: opts.Auth.Username,
		Password: opts.Auth.Password,
	}

	// Extract database name from connection string
	if uri, err := url.Parse(connString); err == nil {
		config.Database = strings.TrimPrefix(uri.Path, "/")
	}

	return config, nil
}
