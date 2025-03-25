package oauth

import (
	"context"
	"encoding/json"
	"github.com/centralmind/gateway/connectors"
	"net/http"
	"net/url"
	"strings"

	"github.com/centralmind/gateway/errors"
	"github.com/centralmind/gateway/model"
	"github.com/centralmind/gateway/xcontext"
	"golang.org/x/oauth2"
	"golang.org/x/xerrors"
)

type Connector struct {
	connectors.Connector
	config      Config
	oauthConfig *oauth2.Config
}

func (c *Connector) Query(ctx context.Context, endpoint model.Endpoint, params map[string]any) ([]map[string]any, error) {
	// Get token from header
	authHeader := xcontext.Header(ctx, c.config.TokenHeader)
	if authHeader == "" {
		ss, ok := authorizedSessions.Load(xcontext.Session(ctx))
		if !ok {
			return nil, xerrors.Errorf("empty authorization: %w", errors.ErrNotAuthorized)
		}
		authHeader = ss.(string)
	}

	// Extract token from "Bearer <token>" header
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return nil, xerrors.Errorf("invalid authorization header format: %w", errors.ErrNotAuthorized)
	}
	tokenString := parts[1]

	// Validate token through provider
	userInfo, err := c.validateToken(ctx, tokenString)
	if err != nil {
		return nil, xerrors.Errorf("token validation failed: %w", err)
	}

	ctx = xcontext.WithClaims(ctx, userInfo)
	if err := c.checkAuthorization(endpoint.MCPMethod, userInfo, params); err != nil {
		return nil, xerrors.Errorf("unable to authorize: %w", err)
	}
	return c.Connector.Query(ctx, endpoint, params)
}

// validateToken makes a request to IDP to validate the token
func (c *Connector) validateToken(ctx context.Context, token string) (map[string]any, error) {
	provider := strings.ToLower(c.config.Provider)
	endpoint := ""

	tokenMethod := "POST"
	switch provider {
	case "github":
		endpoint = "https://api.github.com/user"
		tokenMethod = "GET"
	case "google":
		endpoint = "https://www.googleapis.com/oauth2/v3/userinfo"
	case "auth0":
		endpoint = c.config.UserInfoURL
	case "keycloak", "okta":
		endpoint = c.config.IntrospectionURL
	default:
		return nil, xerrors.Errorf("unsupported provider: %s", provider)
	}

	// Если провайдер поддерживает introspection, делаем POST-запрос
	if provider == "keycloak" || provider == "okta" {
		form := url.Values{}
		form.Set("token", token)
		req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(form.Encode()))
		if err != nil {
			return nil, err
		}
		req.SetBasicAuth(c.config.ClientID, c.config.ClientSecret)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, xerrors.Errorf("introspection request failed: %d", resp.StatusCode)
		}

		var tokenData map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&tokenData); err != nil {
			return nil, err
		}

		if active, ok := tokenData["active"].(bool); !ok || !active {
			return nil, xerrors.Errorf("token is not active")
		}

		return tokenData, nil
	}

	req, err := http.NewRequestWithContext(ctx, tokenMethod, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, xerrors.Errorf("userinfo request failed: %d: %w", resp.StatusCode, errors.ErrNotAuthorized)
	}

	var userInfo map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, err
	}

	return userInfo, nil
}
