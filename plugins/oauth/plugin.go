package oauth

import (
	"context"
	_ "embed"
	"fmt"
	"github.com/centralmind/gateway/mcp"
	"github.com/centralmind/gateway/model"
	"github.com/centralmind/gateway/xcontext"
	"github.com/danielgtaylor/huma/v2"
	"net/http"
	"net/url"

	"github.com/centralmind/gateway/connectors"
	"github.com/centralmind/gateway/plugins"
	"golang.org/x/oauth2"
	"golang.org/x/xerrors"
)

//go:embed README.md
var docString string

var (
	tools  []model.Endpoint
	tooler plugins.MCPTooler
)

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

func (p *Plugin) EnrichMCP(t plugins.MCPTooler) {
	tooler = t
	tools = tooler.Tools()
	tooler.SetTools(nil)
	tooler.Server().DeleteTools("list_tables", "discover_data", "prepare_query", "query")
	u, _ := url.Parse(p.config.RedirectURL)
	tooler.Server().AddTool(mcp.NewTool(
		"authorize",
		mcp.WithDescription(fmt.Sprintf(`
This method will enable other tools and method inside MCP, should be called at very first tool ever called by a user.

This tool require manual action from user, generate for user an ask to go via link to auth a tool.

Link is generated via tool call
`)),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				mcp.TextContent{
					Type: "text",
					Text: fmt.Sprintf("Link is follows: [auth](%s://%s%s?mcp_session=%s)", u.Scheme, u.Host, p.config.AuthURL, xcontext.Session(ctx)),
				},
			},
		}, nil
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
