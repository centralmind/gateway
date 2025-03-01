package restgenerator

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"

	"github.com/centralmind/gateway/connectors"
	gw_errors "github.com/centralmind/gateway/errors"
	gw_model "github.com/centralmind/gateway/model"
	"github.com/centralmind/gateway/plugins"
	"github.com/centralmind/gateway/swaggerator"
	"github.com/centralmind/gateway/xcontext"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"golang.org/x/xerrors"
)

// Rest handles OpenAPI schema generation and sample data serving.
type Rest struct {
	Schema       gw_model.Config
	interceptors []plugins.Interceptor
	connector    connectors.Connector
}

// New initializes a new Rest instance.
func New(
	schema gw_model.Config,
) (*Rest, error) {
	var interceptors []plugins.Interceptor
	for k, v := range schema.Plugins {
		plugin, err := plugins.New(k, v)
		if err != nil {
			return nil, err
		}
		interceptor, ok := plugin.(plugins.Interceptor)
		if !ok {
			continue
		}
		interceptors = append(interceptors, interceptor)
	}
	connector, err := connectors.New(schema.Database.Type, schema.Database.Connection)
	if err != nil {
		return nil, xerrors.Errorf("unable to init connector: %w", err)
	}
	connector, err = plugins.Wrap(schema.Plugins, connector)
	if err != nil {
		return nil, xerrors.Errorf("unable to init connector plugins: %w", err)
	}
	if err := connector.Ping(context.Background()); err != nil {
		return nil, xerrors.Errorf("unable to ping: %w", err)
	}
	return &Rest{
		Schema:       schema,
		interceptors: interceptors,
		connector:    connector,
	}, nil
}

// RegisterRoutes registers Rest endpoints.
func (r *Rest) RegisterRoutes(mux *http.ServeMux, disableSwagger bool, addresses ...string) error {
	if err := plugins.Routes(r.Schema.Plugins, mux); err != nil {
		return xerrors.Errorf("unable to register plugin routes: %w", err)
	}

	// Pass all addresses to swaggerator.Schema
	swagger, err := swaggerator.Schema(r.Schema, addresses...)
	if err != nil {
		return xerrors.Errorf("unable to build swagger doc: %w", err)
	}
	raw, err := json.Marshal(swagger)
	if err != nil {
		return xerrors.Errorf("unable to build swagger: %w", err)
	}

	if !disableSwagger {
		mux.Handle("/swagger/", http.StripPrefix("/swagger", swaggerator.Handler(raw)))
	}
	
	d := gin.Default()
	for _, table := range r.Schema.Database.Tables {
		for _, endpoint := range table.Endpoints {
			d.Handle(endpoint.HTTPMethod, convertSwaggerToGin(endpoint.HTTPPath), r.Handler(endpoint))
		}
	}

	// Add redirect from root to swagger UI only if swagger is enabled
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "" || r.URL.Path == "/" {
			if !disableSwagger {
				http.Redirect(w, r, "/swagger/", http.StatusFound)
				return
			}
			// If swagger is disabled, return 404 for root path
			http.NotFound(w, r)
			return
		}
		d.Handler().ServeHTTP(w, r)
	})

	return nil
}

func (r *Rest) Handler(endpoint gw_model.Endpoint) gin.HandlerFunc {
	return func(c *gin.Context) {
		params := make(map[string]any)
		ctx := c.Request.Context()
		ctx = xcontext.WithHeader(ctx, c.Request.Header)
		for _, param := range c.Params {
			params[param.Key] = param.Value
		}

		for key, values := range c.Request.URL.Query() {
			if len(values) == 1 {
				params[key] = values[0]
			} else {
				params[key] = values
			}
		}
		for _, param := range endpoint.Params {
			if _, ok := params[param.Name]; !ok {
				params[param.Name] = nil
			}
		}

		raw, err := r.connector.Query(ctx, endpoint, params)
		if err != nil {
			code := http.StatusInternalServerError
			if errors.Is(err, gw_errors.ErrNotAuthorized) {
				code = http.StatusUnauthorized
			}
			c.JSON(code, gin.H{"error": err.Error()})
			return
		}
		var res []map[string]any
	MAIN:
		for _, row := range raw {
			for _, interceptor := range r.interceptors {
				r, skip := interceptor.Process(row, c.Request.Header)
				if skip {
					continue MAIN
				}
				row = r
			}
			res = append(res, row)
		}
		if !endpoint.IsArrayResult {
			if len(res) == 0 {
				c.JSON(http.StatusNotFound, gin.H{})
				return
			}
			if len(res) >= 1 {
				c.JSON(http.StatusOK, res[0])
				return
			}
		}
		c.JSON(http.StatusOK, res)
	}
}

func convertSwaggerToGin(swaggerURL string) string {
	re := regexp.MustCompile(`\{([^}]+)\}`)
	return re.ReplaceAllString(swaggerURL, ":$1")
}
