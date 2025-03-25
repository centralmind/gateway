package plugins

import (
	"github.com/centralmind/gateway/server"
	"github.com/danielgtaylor/huma/v2"
	"net/http"

	"github.com/centralmind/gateway/connectors"
	"github.com/centralmind/gateway/remapper"
	"golang.org/x/xerrors"
)

// Config defines the basic configuration interface that all plugin configs must implement
type Config interface {
	// Tag returns the unique identifier for the plugin
	Tag() string
	Doc() string
}

// Plugin is the base interface that all plugins must implement
type Plugin interface {
	// Doc returns the documentation string describing plugin's purpose and configuration
	Doc() string
}

// Interceptor represents a plugin that can process and modify data before it reaches the connector
type Interceptor interface {
	Plugin
	// Process handles the data transformation and returns processed data and a skip flag
	// data: the input data to be processed
	// context: additional context information as key-value pairs
	// Returns: processed data and a boolean indicating if further processing should be skipped
	Process(data map[string]any, context map[string][]string) (procesed map[string]any, skipped bool)
}

type HTTPServer interface {
	Plugin
	RegisterRoutes(mux *http.ServeMux)
}

type MCPTooler interface {
	Server() *server.MCPServer
}

type MCPToolEnricher interface {
	Plugin
	EnrichMCP(tooler MCPTooler)
}

// Wrapper represents a plugin that can wrap and enhance a connector's functionality
type Wrapper interface {
	Plugin
	// Wrap takes a connector and returns an enhanced version of it
	// Returns: wrapped connector or error if wrapping fails
	Wrap(connector connectors.Connector) (connectors.Connector, error)
}

// Swaggerer represents a plugin that can modify OpenAPI documentation
type Swaggerer interface {
	Plugin
	// Enrich enhances the OpenAPI documentation with additional specifications
	// Returns: modified OpenAPI documentation
	Enrich(swag *huma.OpenAPI) *huma.OpenAPI
}

var (
	plugins = map[string]func(any) (Plugin, error){}
	configs = map[string]Config{}
)

type PluginF[TConfig Config, TPlugin Plugin] func(cfg TConfig) (TPlugin, error)

func Register[TConfig Config, TPlugin Plugin](f PluginF[TConfig, TPlugin]) {
	var t TConfig
	plugins[t.Tag()] = func(a any) (Plugin, error) {
		cfg, err := remapper.Remap[TConfig](a)
		if err != nil {
			return nil, xerrors.Errorf("unable to rempa: %w", err)
		}
		return f(cfg)
	}
	configs[t.Tag()] = t
}

func New(tag string, config any) (Plugin, error) {
	f, ok := plugins[tag]
	if !ok {
		return nil, xerrors.Errorf("plugin: %s not found", tag)
	}
	return f(config)
}

func Plugins[TPlugin Plugin](pluginsCfg map[string]any) ([]TPlugin, error) {
	var res []TPlugin
	for k, v := range pluginsCfg {
		if _, ok := plugins[k]; !ok {
			continue
		}
		plugin, err := plugins[k](v)
		if err != nil {
			return nil, xerrors.Errorf("unable to construct: %s: %w", k, err)
		}
		p, ok := plugin.(TPlugin)
		if !ok {
			continue
		}
		res = append(res, p)
	}
	return res, nil
}

func Routes(pluginsCfg map[string]any, mux *http.ServeMux) error {
	plugs, err := Plugins[HTTPServer](pluginsCfg)
	if err != nil {
		return err
	}

	for _, plug := range plugs {
		plug.RegisterRoutes(mux)
	}
	return nil
}

func Enrich(pluginsCfg map[string]any, schema *huma.OpenAPI) (*huma.OpenAPI, error) {
	plugs, err := Plugins[Swaggerer](pluginsCfg)
	if err != nil {
		return nil, err
	}
	for _, wrapper := range plugs {
		schema = wrapper.Enrich(schema)
	}
	return schema, nil
}

func Wrap(pluginsCfg map[string]any, connector connectors.Connector) (connectors.Connector, error) {
	plugs, err := Plugins[Wrapper](pluginsCfg)
	if err != nil {
		return nil, err
	}
	for _, wrapper := range plugs {
		connector, err = wrapper.Wrap(connector)
		if err != nil {
			return nil, xerrors.Errorf("unable to wrap: %T: %w", wrapper, err)
		}
	}
	return connector, nil
}

// KnownPlugins returns a list of all registered plugin configurations
func KnownPlugins() []Config {
	result := make([]Config, 0, len(plugins))
	for tag := range plugins {
		result = append(result, configs[tag])
	}
	return result
}

// KnownPlugin returns configuration for a specific plugin by tag
func KnownPlugin(tag string) (Config, bool) {
	cfg, ok := configs[tag]
	if !ok {
		return nil, false
	}
	return cfg, true
}
