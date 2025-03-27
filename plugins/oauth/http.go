package oauth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// for now - global var, better to replace with shared DB
var (
	authorizedSessions   = sync.Map{}
	authorizedSessionsWG = sync.Map{}
)

// generateState creates a random state parameter to prevent CSRF
func generateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

type AuthResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in,omitempty"`
}

func (p *Plugin) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	// Generate state parameter
	state, err := generateState()
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Store state in cookie for validation during callback
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		Path:     "/",
		Expires:  time.Now().Add(15 * time.Minute),
		HttpOnly: true,
		Secure:   r.TLS != nil,
	})
	if r.URL.Query().Get("mcp_session") != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     "mcp_session",
			Value:    r.URL.Query().Get("mcp_session"),
			Path:     "/",
			Expires:  time.Now().Add(15 * time.Minute),
			HttpOnly: true,
			Secure:   r.TLS != nil,
		})
	}

	redirectURL := r.URL.Query().Get("redirect_uri")
	p.oauthConfig.RedirectURL = redirectURL
	authURL := p.oauthConfig.AuthCodeURL(state)

	// Build authorization URL
	if redirectURL != "" {
		cfg := p.oauthConfig
		cfg.RedirectURL = redirectURL
		authURL = cfg.AuthCodeURL(state)
	}

	// Redirect to provider's consent page
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

func (p *Plugin) HandleCallback(w http.ResponseWriter, r *http.Request) {
	// Verify state parameter
	stateCookie, err := r.Cookie("oauth_state")
	if err != nil {
		http.Error(w, "State cookie not found", http.StatusBadRequest)
		return
	}

	if r.URL.Query().Get("state") != stateCookie.Value {
		http.Error(w, "State mismatch", http.StatusBadRequest)
		return
	}

	// Clear state cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    "",
		Path:     "/",
		Expires:  time.Now().Add(-1 * time.Hour),
		HttpOnly: true,
		Secure:   r.TLS != nil,
	})

	// Exchange code for token
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Code not found", http.StatusBadRequest)
		return
	}

	token, err := p.oauthConfig.Exchange(r.Context(), code)
	if err != nil {
		http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
		return
	}

	// Return token as JSON
	response := AuthResponse{
		AccessToken: token.AccessToken,
		TokenType:   "Bearer",
	}

	if mcpSession, err := r.Cookie("mcp_session"); err == nil && mcpSession.Value != "" {
		authorizedSessions.LoadOrStore(mcpSession.Value, "Bearer "+token.AccessToken)
		waiter, ok := authorizedSessionsWG.Load(mcpSession.Value)
		if ok {
			_, okok := authorizedSessions.Load(mcpSession.Value)
			if !okok {
				waiter.(*sync.WaitGroup).Done()
			}
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")

		// Read HTML template from embedded resources
		htmlContent, err := resources.ReadFile("resources/auth_complete.html")
		if err != nil {
			http.Error(w, "Failed to load template", http.StatusInternalServerError)
			return
		}

		_, _ = w.Write(htmlContent)
		return
	}

	if !token.Expiry.IsZero() {
		response.ExpiresIn = int(time.Until(token.Expiry).Seconds())
	}

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "    ")
	if err := enc.Encode(response); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}
