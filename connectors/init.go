package connectors

import (
	"context"

	"github.com/centralmind/gateway/model"
	"github.com/centralmind/gateway/remapper"
	"golang.org/x/xerrors"
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
	Discovery(ctx context.Context, tablesList []string) ([]model.Table, error)
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

// RegisterAlias registers additional names for an existing connector type
func RegisterAlias(typ string, aliases ...string) {
	f, ok := interceptors[typ]
	if !ok {
		return
	}
	cfg, ok := configs[typ]
	if !ok {
		return
	}
	for _, alias := range aliases {
		interceptors[alias] = f
		configs[alias] = cfg
	}
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

func New(tag string, config any) (Connector, error) {
	// Note: Environment variable expansion is now handled at the model level
	// in model/model.go, so we no longer need to do it here
	f, ok := interceptors[tag]
	if !ok {
		return nil, xerrors.Errorf("connector: %s not found", tag)
	}
	return f(config)
}
