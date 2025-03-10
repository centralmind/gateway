package oauth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"
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

	// Build authorization URL
	authURL := p.oauthConfig.AuthCodeURL(state)

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
