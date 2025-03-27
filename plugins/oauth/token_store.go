package oauth

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// TokenInfo contains information about an issued token
type TokenInfo struct {
	// Access token
	AccessToken string

	// Type of token (typically "Bearer")
	TokenType string

	// Expiration time (Unix timestamp)
	ExpiresAt int64

	// Associated refresh token, if any
	RefreshToken string

	// Client ID this token was issued to
	ClientID string

	// Subject (user) this token was issued for
	Subject string

	// Scopes granted to this token
	Scopes []string
}

// TokenStore is an interface for storing and retrieving tokens
type TokenStore interface {
	// StoreAccessToken stores an access token and related info
	StoreAccessToken(token TokenInfo) error

	// GetAccessToken retrieves token info for an access token
	GetAccessToken(token string) (*TokenInfo, error)

	// GetRefreshToken retrieves token info for a refresh token
	GetRefreshToken(token string) (*TokenInfo, error)

	// RevokeAccessToken revokes an access token
	RevokeAccessToken(token string) error

	// RevokeRefreshToken revokes a refresh token
	RevokeRefreshToken(token string) error
}

// InMemoryTokenStore is a simple in-memory implementation of TokenStore
type InMemoryTokenStore struct {
	accessTokens  map[string]TokenInfo
	refreshTokens map[string]string // maps refresh tokens to access tokens
	mu            sync.RWMutex
}

// NewInMemoryTokenStore creates a new in-memory token store
func NewInMemoryTokenStore() *InMemoryTokenStore {
	return &InMemoryTokenStore{
		accessTokens:  make(map[string]TokenInfo),
		refreshTokens: make(map[string]string),
	}
}

// StoreAccessToken stores an access token and related info
func (s *InMemoryTokenStore) StoreAccessToken(token TokenInfo) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.accessTokens[token.AccessToken] = token

	if token.RefreshToken != "" {
		s.refreshTokens[token.RefreshToken] = token.AccessToken
	}

	return nil
}

// GetAccessToken retrieves token info for an access token
func (s *InMemoryTokenStore) GetAccessToken(token string) (*TokenInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	info, exists := s.accessTokens[token]
	if !exists {
		return nil, ErrInvalidToken
	}

	// Check if token has expired
	if info.ExpiresAt < time.Now().Unix() {
		return nil, ErrTokenExpired
	}

	return &info, nil
}

// GetRefreshToken retrieves token info for a refresh token
func (s *InMemoryTokenStore) GetRefreshToken(refreshToken string) (*TokenInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	accessToken, exists := s.refreshTokens[refreshToken]
	if !exists {
		return nil, ErrInvalidToken
	}

	info, exists := s.accessTokens[accessToken]
	if !exists {
		// This should not happen in normal conditions
		return nil, ErrInvalidToken
	}

	return &info, nil
}

// RevokeAccessToken revokes an access token
func (s *InMemoryTokenStore) RevokeAccessToken(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	info, exists := s.accessTokens[token]
	if !exists {
		return ErrInvalidToken
	}

	delete(s.accessTokens, token)

	// Also remove the refresh token if it exists
	if info.RefreshToken != "" {
		delete(s.refreshTokens, info.RefreshToken)
	}

	return nil
}

// RevokeRefreshToken revokes a refresh token
func (s *InMemoryTokenStore) RevokeRefreshToken(refreshToken string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	accessToken, exists := s.refreshTokens[refreshToken]
	if !exists {
		return ErrInvalidToken
	}

	// Remove the refresh token
	delete(s.refreshTokens, refreshToken)

	// Update the access token entry to remove the refresh token reference
	if tokenInfo, ok := s.accessTokens[accessToken]; ok {
		tokenInfo.RefreshToken = ""
		s.accessTokens[accessToken] = tokenInfo
	}

	return nil
}

// GenerateAccessToken generates a secure random access token
func GenerateAccessToken() (string, error) {
	return generateSecureToken(32)
}

// GenerateRefreshToken generates a secure random refresh token
func GenerateRefreshToken() (string, error) {
	return generateSecureToken(32)
}

// generateSecureToken creates a cryptographically secure random token
func generateSecureToken(length int) (string, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b), nil
}
