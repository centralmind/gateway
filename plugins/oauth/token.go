package oauth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2"
	"net/http"
	"time"
)

// TokenResponse represents the response from the token endpoint
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// TokenRequest represents a request to the token endpoint
type TokenRequest struct {
	GrantType    string `json:"grant_type"`
	Code         string `json:"code,omitempty"`
	CodeVerifier string `json:"code_verifier,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
	RedirectURI  string `json:"redirect_uri,omitempty"`
}

// TokenHandlerOptions contains options for the token endpoint handler
type TokenHandlerOptions struct {
	// TokenStore for managing tokens (this would be expanded in a real implementation)
	TokenStore TokenStore

	// RateLimitRequests is the maximum number of requests per window
	// If 0, rate limiting is disabled
	RateLimitRequests float64
}

// HandleToken handles OAuth token requests
func (p *Plugin) HandleToken(w http.ResponseWriter, r *http.Request) {
	// Set cache control header to prevent caching
	w.Header().Set("Cache-Control", "no-store")

	// Only allow POST method (OPTIONS is handled by the middleware)
	if r.Method != "POST" {
		w.Header().Set("Allow", "POST, OPTIONS")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Apply rate limiting if enabled
	if p.tokenRateLimiter != nil {
		clientIP := r.RemoteAddr
		if !p.tokenRateLimiter.Allow(clientIP) {
			respondWithError(w, ErrRateLimitExceeded, http.StatusTooManyRequests)
			return
		}
	}

	// Parse form data
	if err := r.ParseForm(); err != nil {
		respondWithError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	// Extract token request parameters
	tokenRequest := TokenRequest{
		GrantType:    r.FormValue("grant_type"),
		Code:         r.FormValue("code"),
		CodeVerifier: r.FormValue("code_verifier"),
		RefreshToken: r.FormValue("refresh_token"),
		Scope:        r.FormValue("scope"),
		RedirectURI:  r.FormValue("redirect_uri"),
	}

	// Validate grant_type (required parameter)
	if tokenRequest.GrantType == "" {
		respondWithError(w, ErrInvalidRequest.WithDescription("grant_type is required"), http.StatusBadRequest)
		return
	}

	// Process based on grant type
	switch tokenRequest.GrantType {
	case "authorization_code":
		p.handleAuthorizationCodeGrant(w, r, tokenRequest)
	case "refresh_token":
		p.handleRefreshTokenGrant(w, r, tokenRequest)
	default:
		respondWithError(w, ErrUnsupportedGrantType, http.StatusBadRequest)
	}
}

// handleAuthorizationCodeGrant processes authorization_code grant requests
func (p *Plugin) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request, req TokenRequest) {
	// Validate required parameters
	if req.Code == "" {
		respondWithError(w, ErrInvalidRequest.WithDescription("code is required"), http.StatusBadRequest)
		return
	}

	if req.CodeVerifier == "" {
		respondWithError(w, ErrInvalidRequest.WithDescription("code_verifier is required"), http.StatusBadRequest)
		return
	}

	token, err := p.oauthConfig.Exchange(
		r.Context(),
		req.Code,
		oauth2.VerifierOption(req.CodeVerifier),
	)
	if err != nil {
		respondWithError(w, ErrInvalidRequest.WithDescription(fmt.Sprintf("exchange failed with: %s", err.Error())), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(token)
}

// handleRefreshTokenGrant processes refresh_token grant requests
func (p *Plugin) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request, req TokenRequest) {
	// Validate required parameters
	if req.RefreshToken == "" {
		respondWithError(w, ErrInvalidRequest.WithDescription("refresh_token is required"), http.StatusBadRequest)
		return
	}

	token, err := p.oauthConfig.Exchange(
		r.Context(),
		req.Code,
		oauth2.VerifierOption(req.CodeVerifier),
	)
	if err != nil {
		respondWithError(w, ErrInvalidRequest.WithDescription(fmt.Sprintf("exchange failed with: %s", err.Error())), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(token)
}

// SetupTokenHandler configures the token endpoint handler
func (p *Plugin) SetupTokenHandler(options TokenHandlerOptions) http.Handler {
	// Store options in plugin
	p.tokenOptions = options

	// Create rate limiter if enabled
	if options.RateLimitRequests > 0 {
		p.tokenRateLimiter = NewSimpleRateLimiter(time.Minute*15, options.RateLimitRequests)
	}

	// Create handler
	return http.HandlerFunc(p.HandleToken)
}

// generateRandomToken creates a random token
func generateRandomToken() string {
	token, err := GenerateAccessToken()
	if err != nil {
		// Fallback to a simple method in case of error
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		return base64.URLEncoding.EncodeToString(b)
	}
	return token
}
