package elasticsearch

import (
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"fmt"
	"gopkg.in/yaml.v3"
	"net/http"
	"strings"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/pkg/errors"
)

//go:embed readme.md
var docString string

type Config struct {
	Hosts      []string `yaml:"hosts"`     // List of Elasticsearch nodes (e.g., ["http://localhost:9200"])
	Username   string   `yaml:"user"`      // Elasticsearch username (if authentication is enabled)
	Password   string   `yaml:"password"`  // Elasticsearch password
	EnableTLS  bool     `yaml:"enableTLS"` // Enable TLS/SSL connection
	CertFile   string   `yaml:"certFile"`
	IsReadonly bool     `yaml:"is_readonly"`
}

func (c Config) Readonly() bool {
	return c.IsReadonly
}

func (c Config) ExtraPrompt() []string {
	return []string{
		"Database: Elasticsearch (NoSQL search engine).",
		"Queries must use Elasticsearch Query DSL in JSON format.",
		"Paginate with 'from' and 'size' instead of 'offset' and 'limit'.",
		"Elasticsearch Query DSL with Mustache templating syntax.",
		"Elasticsearch queries are written as JSON objects and sent to the _search/template endpoint.",
		"For Elasticsearch, queries must be written using Mustache syntax.",
		"Use double curly braces {{param}} for dynamic variables.",
		"Hierarchical data should use 'nested' fields or parent-child relationships.",
		"The final output must contain *only valid single JSON* with no additional commentary, explanations, or markdown formatting!",
	}
}

// TLSConfig generates TLS settings
func (c Config) TLSConfig() (*tls.Config, error) {
	if !c.EnableTLS {
		return nil, nil
	}

	rootCertPool := x509.NewCertPool()
	if len(c.CertFile) > 0 {
		ok := rootCertPool.AppendCertsFromPEM([]byte(c.CertFile))
		if !ok {
			return nil, errors.New("unable to add TLS certificate to cert pool")
		}
	}

	return &tls.Config{
		RootCAs:            rootCertPool,
		InsecureSkipVerify: len(c.CertFile) == 0,
	}, nil
}

// UnmarshalYAML allows parsing either a direct connection string or a full configuration object.
func (c *Config) UnmarshalYAML(value *yaml.Node) error {
	// Attempt to parse as a single connection string (e.g., "http://user:pass@localhost:9200")
	var connString string
	if err := value.Decode(&connString); err == nil {
		// If it's a valid connection string, extract components
		esConfig, err := parseElasticsearchConnString(connString)
		if err != nil {
			return err
		}

		c.Hosts = esConfig.Addresses
		c.Username = esConfig.Username
		c.Password = esConfig.Password
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

// MakeConfig constructs an Elasticsearch configuration
func (c Config) MakeConfig() (*elasticsearch.Config, error) {
	if len(c.Hosts) == 0 {
		return nil, errors.New("no Elasticsearch hosts provided")
	}

	// Ensure correct protocol handling
	addresses := make([]string, len(c.Hosts))
	for i, host := range c.Hosts {
		if !strings.HasPrefix(host, "http://") && !strings.HasPrefix(host, "https://") {
			protocol := "http"
			if c.EnableTLS {
				protocol = "https"
			}
			host = fmt.Sprintf("%s://%s", protocol, host)
		}
		addresses[i] = host
	}

	tlsConfig, err := c.TLSConfig()
	if err != nil {
		return nil, err
	}

	return &elasticsearch.Config{
		Addresses: addresses,
		Username:  c.Username,
		Password:  c.Password,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}, nil
}

func (c Config) Type() string {
	return "elasticsearch"
}

func (c Config) Doc() string {
	return docString
}

// parseElasticsearchConnString parses the connection string into an Elasticsearch Config
func parseElasticsearchConnString(connString string) (*elasticsearch.Config, error) {
	if !strings.HasPrefix(connString, "http://") && !strings.HasPrefix(connString, "https://") {
		return nil, errors.New("invalid Elasticsearch connection string format")
	}

	var username, password, host string
	host = connString

	if strings.Contains(connString, "@") {
		parts := strings.SplitN(connString, "@", 2)
		authParts := strings.SplitN(parts[0], "://", 2)
		if len(authParts) == 2 {
			creds := strings.SplitN(authParts[1], ":", 2)
			if len(creds) == 2 {
				username = creds[0]
				password = creds[1]
			}
		}
		host = parts[1]
	}

	return &elasticsearch.Config{
		Addresses: []string{host},
		Username:  username,
		Password:  password,
	}, nil
}
