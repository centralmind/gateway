package connectors

import (
	"context"
	"os"
	"strings"

	"github.com/centralmind/gateway/model"
	"github.com/centralmind/gateway/remapper"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"
)

type Config interface {
	Type() string
	Doc() string
	ExtraPrompt() []string
	Readonly() bool
}

type Connector interface {
	Ping(ctx context.Context) error
	Query(ctx context.Context, endpoint model.Endpoint, params map[string]any) ([]map[string]any, error)
	Discovery(ctx context.Context) ([]model.Table, error)
	Sample(ctx context.Context, table model.Table) ([]map[string]any, error)
	InferQuery(ctx context.Context, query string) ([]model.ColumnSchema, error)
	Config() Config
}

var interceptors = map[string]func(any) (Connector, error){}
var configs = map[string]Config{}

func Register[TConfig Config](f func(cfg TConfig) (Connector, error)) {
	var t TConfig
	interceptors[t.Type()] = func(a any) (Connector, error) {
		cfg, err := remapper.Remap[TConfig](a)
		if err != nil {
			return nil, xerrors.Errorf("unable to remap: %w", err)
		}
		return f(cfg)
	}
	configs[t.Type()] = t
}

// KnownConnectors returns a list of all registered connector configurations
func KnownConnectors() []Config {
	result := make([]Config, 0, len(configs))
	for _, cfg := range configs {
		result = append(result, cfg)
	}
	return result
}

func KnownConnector(key string) (Config, bool) {
	cfg, ok := configs[key]
	return cfg, ok
}

// expandEnvIfNotQuoted expands environment variables in a string only if it's not quoted
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

func New(tag string, config any) (Connector, error) {
	switch v := config.(type) {
	case string:
		var node yaml.Node
		if err := yaml.Unmarshal([]byte(v), &node); err != nil {
			return nil, err
		}
		expandEnvIfNotQuoted(&node)
		var r any
		if err := node.Decode(&r); err != nil {
			return nil, err
		}
		config = r
	case []byte:
		var node yaml.Node
		if err := yaml.Unmarshal(v, &node); err != nil {
			return nil, err
		}
		expandEnvIfNotQuoted(&node)
		var r any
		if err := node.Decode(&r); err != nil {
			return nil, err
		}
		config = r
	}
	f, ok := interceptors[tag]
	if !ok {
		return nil, xerrors.Errorf("connector: %s not found", tag)
	}
	return f(config)
}
