package oauth

import (
	"context"
	_ "embed"
	"errors"
	gerrors "github.com/centralmind/gateway/errors"
	"github.com/centralmind/gateway/mcp"
	"github.com/centralmind/gateway/server"
	"github.com/centralmind/gateway/xcontext"
	"github.com/danielgtaylor/huma/v2"
	"net/http"
	"net/url"
	"sync"

	"github.com/centralmind/gateway/connectors"
	"github.com/centralmind/gateway/plugins"
	"golang.org/x/oauth2"
	"golang.org/x/xerrors"
)

//go:embed README.md
var docString string

func init() {
	plugins.Register(New)
}

type PluginBundle interface {
	plugins.Wrapper
	plugins.Swaggerer
	plugins.HTTPServer
	plugins.MCPToolEnricher
}

func New(cfg Config) (PluginBundle, error) {
	cfg.WithDefaults()
	oauthConfig := cfg.GetOAuthConfig()
	if oauthConfig == nil {
		return nil, xerrors.New("failed to create OAuth config")
	}

	plugin := &Plugin{
		config:      cfg,
		oauthConfig: oauthConfig,
	}

	return plugin, nil
}

type Plugin struct {
	config      Config
	oauthConfig *oauth2.Config
}

func (p *Plugin) EnrichMCP(tooler plugins.MCPTooler) {
	u, _ := url.Parse(p.config.RedirectURL)
	tooler.Server().AddToolMiddleware(func(ctx context.Context, tool server.ServerTool, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		waiter, ok := authorizedSessionsWG.Load(xcontext.Session(ctx))
		if ok {
			waiter.(*sync.WaitGroup).Wait()
		}
		r, err := tool.Handler(ctx, request)
		if err != nil {
			if errors.Is(err, gerrors.ErrNotAuthorized) {
				authorizedSessionsWG.Store(xcontext.Session(ctx), &sync.WaitGroup{})
				return nil, xerrors.Errorf(
					`
This tool require manual action from user, generate for user an ask to go via link to auth a tool.
Link is follows: [auth](%s://%s%s?mcp_session=%s)
Prompt to user a link as markdown link above.

!Important, client must retry this call, no need to wait instructions from user.
`,
					u.Scheme,
					u.Host,
					p.config.AuthURL,
					xcontext.Session(ctx),
				)
			}
			return nil, err
		}
		return r, nil
	})
}

func (p *Plugin) RegisterRoutes(mux *http.ServeMux) {
	if p.config.AuthURL == "" || p.config.CallbackURL == "" {
		return
	}
	// Register HTTP handlers
	mux.HandleFunc(p.config.AuthURL, p.HandleAuthorize)
	mux.HandleFunc(p.config.CallbackURL, p.HandleCallback)
}

func (p *Plugin) Doc() string {
	return docString
}

func (p *Plugin) Wrap(connector connectors.Connector) (connectors.Connector, error) {
	return &Connector{
		Connector:   connector,
		config:      p.config,
		oauthConfig: p.oauthConfig,
	}, nil
}

func (p *Plugin) Enrich(swag *huma.OpenAPI) *huma.OpenAPI {
	// Add OAuth2 security definition
	if swag.Components.SecuritySchemes == nil {
		swag.Components.SecuritySchemes = map[string]*huma.SecurityScheme{}
	}

	scopes := map[string]string{}
	for _, scope := range p.oauthConfig.Scopes {
		scopes[scope] = ""
	}

	swag.Components.SecuritySchemes["OAuth2"] = &huma.SecurityScheme{
		Type:        "oauth2",
		Description: "OAuth2 authentication",
		Flows: &huma.OAuthFlows{
			AuthorizationCode: &huma.OAuthFlow{
				AuthorizationURL: p.oauthConfig.Endpoint.AuthURL,
				TokenURL:         p.oauthConfig.Endpoint.TokenURL,
				Scopes:           scopes,
			},
		},
	}

	// Add security requirements to all paths
	for _, pathItem := range swag.Paths {
		for _, op := range []*huma.Operation{
			pathItem.Get,
			pathItem.Post,
			pathItem.Put,
			pathItem.Delete,
			pathItem.Patch,
		} {
			if op != nil {
				op.Security = []map[string][]string{
					{
						"OAuth2": []string{},
					},
				}
			}
		}
	}

	return swag
}
