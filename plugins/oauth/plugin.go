package oauth

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	gerrors "github.com/centralmind/gateway/errors"
	"github.com/centralmind/gateway/mcp"
	"github.com/centralmind/gateway/server"
	"github.com/centralmind/gateway/xcontext"
	"github.com/danielgtaylor/huma/v2"

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

	// Initialize client store if client registration is enabled
	if cfg.ClientRegistration.Enabled {
		// Set registration options
		plugin.registrationOptions = RegistrationHandlerOptions{
			ClientSecretExpirySeconds: cfg.ClientRegistration.ClientSecretExpirySeconds,
			RateLimitRequests:         cfg.ClientRegistration.RateLimitRequestsPerHour,
		}

		// Initialize rate limiter if configured
		if cfg.ClientRegistration.RateLimitRequestsPerHour > 0 {
			plugin.registrationRateLimiter = NewSimpleRateLimiter(time.Hour, cfg.ClientRegistration.RateLimitRequestsPerHour)
		}
	}

	return plugin, nil
}

type Plugin struct {
	config                  Config
	oauthConfig             *oauth2.Config
	tokenStore              TokenStore
	registrationOptions     RegistrationHandlerOptions
	registrationRateLimiter *SimpleRateLimiter
	tokenOptions            TokenHandlerOptions
	tokenRateLimiter        *SimpleRateLimiter
}

func (p *Plugin) EnrichMCP(tooler plugins.MCPTooler) {
	u, _ := url.Parse(p.config.RedirectURL)
	tooler.Server().AddAuthorizer(func(r *http.Request) bool {
		if r.Header.Get("Authorization") == "" {
			return false
		}
		_, err := validateToken(
			r.Context(),
			p.config,
			strings.Replace(r.Header.Get("Authorization"), "Bearer ", "", 1),
		)
		if err != nil {
			return false
		}
		return true
	})
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
	rUrl, err := url.Parse(p.config.IssuerURL)
	if err != nil {
		return
	}
	// Register HTTP handlers with CORS middleware
	mux.Handle(p.config.AuthURL, CORSMiddleware(http.HandlerFunc(p.HandleAuthorize)))
	mux.Handle(p.config.CallbackURL, CORSMiddleware(http.HandlerFunc(p.HandleCallback)))

	// Initialize token store if not already set
	if p.tokenStore == nil {
		p.tokenStore = NewInMemoryTokenStore()
	}

	// Set up and register the token endpoint
	tokenPath := p.config.TokenURL // Use the configured token URL

	// Configure token handler options
	p.tokenOptions = TokenHandlerOptions{
		TokenStore:        p.tokenStore,
		RateLimitRequests: 50, // 50 requests per 15 minute window
	}

	// Initialize token rate limiter
	p.tokenRateLimiter = NewSimpleRateLimiter(time.Minute*15, p.tokenOptions.RateLimitRequests)

	// Register the token handler with CORS middleware
	tokenHandler := http.HandlerFunc(p.HandleToken)
	mux.Handle(tokenPath, CORSMiddleware(tokenHandler))

	// Register dynamic client registration endpoint if enabled
	if p.config.ClientRegistration.Enabled {
		// Configure registration handler options
		p.registrationOptions = RegistrationHandlerOptions{
			ClientSecretExpirySeconds: p.config.ClientRegistration.ClientSecretExpirySeconds,
			RateLimitRequests:         p.config.ClientRegistration.RateLimitRequestsPerHour,
		}

		// Initialize rate limiter if configured
		if p.config.ClientRegistration.RateLimitRequestsPerHour > 0 {
			p.registrationRateLimiter = NewSimpleRateLimiter(time.Hour, p.config.ClientRegistration.RateLimitRequestsPerHour)
		}

		// Register the handler with CORS middleware
		registrationHandler := http.HandlerFunc(p.HandleRegister)
		mux.Handle(p.config.RegisterURL, CORSMiddleware(registrationHandler))
	}

	// Register the well-known endpoint with CORS middleware
	mux.Handle("/.well-known/oauth-authorization-server", CORSMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Add registration endpoint to metadata
		var registrationEndpoint string
		if p.config.ClientRegistration.Enabled {
			registrationEndpoint = p.config.RegisterURL
		}

		metadata := NewMetadata(
			*rUrl,
			p.config.AuthURL,
			tokenPath,
			registrationEndpoint,
		)

		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "    ")
		if err := enc.Encode(metadata); err != nil {
			http.Error(w, "Failed to encode response", http.StatusInternalServerError)
			return
		}
	})))
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
