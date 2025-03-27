package oauth

import (
	"encoding/json"
	"github.com/gin-gonic/gin"
	"net/http"
	"sync"
	"time"
)

const (
	// DefaultClientSecretExpirySeconds is the default expiry time for client secrets (30 days)
	DefaultClientSecretExpirySeconds int64 = 30 * 24 * 60 * 60
)

// SimpleRateLimiter implements a basic rate limiter
type SimpleRateLimiter struct {
	mutex      sync.Mutex
	requests   map[string][]time.Time
	windowSize time.Duration
	maxRequest float64
}

// NewSimpleRateLimiter creates a new rate limiter
func NewSimpleRateLimiter(windowSize time.Duration, maxRequest float64) *SimpleRateLimiter {
	return &SimpleRateLimiter{
		requests:   make(map[string][]time.Time),
		windowSize: windowSize,
		maxRequest: maxRequest,
	}
}

// Allow checks if a request should be allowed
func (r *SimpleRateLimiter) Allow(key string) bool {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	now := time.Now()
	cutoff := now.Add(-r.windowSize)

	// Filter out old requests
	validRequests := []time.Time{}
	for _, t := range r.requests[key] {
		if t.After(cutoff) {
			validRequests = append(validRequests, t)
		}
	}

	// Check if under the limit
	if float64(len(validRequests)) < r.maxRequest {
		r.requests[key] = append(validRequests, now)
		return true
	}

	// Keep the existing requests without adding a new one
	r.requests[key] = validRequests
	return false
}

// RegistrationHandlerOptions contains options for the client registration handler
type RegistrationHandlerOptions struct {
	// ClientSecretExpirySeconds is the expiry time for client secrets in seconds
	// If 0, client secrets won't expire (not recommended)
	ClientSecretExpirySeconds int64

	// RateLimitRequests is the maximum number of requests per hour
	// If 0, rate limiting is disabled
	RateLimitRequests float64
}

// HandleRegister handles OAuth client registration requests
func (p *Plugin) HandleRegister(w http.ResponseWriter, r *http.Request) {
	// Set cache control header
	w.Header().Set("Cache-Control", "no-store")

	// Only allow POST method (OPTIONS is handled by the middleware)
	if r.Method != "POST" {
		w.Header().Set("Allow", "POST, OPTIONS")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Apply rate limiting if enabled
	if p.registrationRateLimiter != nil {
		clientIP := r.RemoteAddr
		if !p.registrationRateLimiter.Allow(clientIP) {
			respondWithError(w, ErrRateLimitExceeded, http.StatusTooManyRequests)
			return
		}
	}

	// Parse client metadata from request body
	var clientMetadata OAuthClientMetadata
	err := json.NewDecoder(r.Body).Decode(&clientMetadata)
	if err != nil {
		respondWithError(w, ErrInvalidClientMetadata, http.StatusBadRequest)
		return
	}

	// Validate required fields
	if len(clientMetadata.RedirectURIs) == 0 {
		respondWithError(w, ErrMissingRedirectURIs, http.StatusBadRequest)
		return
	}

	// Set default values if not provided
	if len(clientMetadata.GrantTypes) == 0 {
		clientMetadata.GrantTypes = []string{"authorization_code"}
	}

	if len(clientMetadata.ResponseTypes) == 0 {
		clientMetadata.ResponseTypes = []string{"code"}
	}

	if clientMetadata.TokenEndpointAuthMethod == "" {
		clientMetadata.TokenEndpointAuthMethod = "client_secret_basic"
	}

	// Return client information
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(gin.H{})
}

// SetupRegistrationHandler configures the client registration endpoint
func (p *Plugin) SetupRegistrationHandler(options RegistrationHandlerOptions) http.Handler {
	// Store options in plugin
	p.registrationOptions = options

	// Set default values
	if p.registrationOptions.ClientSecretExpirySeconds == 0 {
		p.registrationOptions.ClientSecretExpirySeconds = DefaultClientSecretExpirySeconds
	}

	// Create rate limiter if enabled
	if options.RateLimitRequests > 0 {
		p.registrationRateLimiter = NewSimpleRateLimiter(time.Hour, options.RateLimitRequests)
	}

	// Create handler
	return http.HandlerFunc(p.HandleRegister)
}

// respondWithError sends an OAuth error response to the client
func respondWithError(w http.ResponseWriter, err error, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(NewOAuthErrorResponse(err))
}
