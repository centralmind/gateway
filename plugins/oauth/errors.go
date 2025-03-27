package oauth

import "errors"

// OAuth error definitions
var (
	// ErrClientNotFound is returned when a client with the specified ID is not found
	ErrClientNotFound = errors.New("oauth client not found")

	// ErrClientSecretExpired is returned when a client's secret has expired
	ErrClientSecretExpired = errors.New("oauth client secret has expired")

	// ErrInvalidClientMetadata is returned when client metadata is invalid
	ErrInvalidClientMetadata = errors.New("invalid oauth client metadata")

	// ErrMissingRedirectURIs is returned when no redirect URIs are provided
	ErrMissingRedirectURIs = errors.New("redirect_uris is required")

	// ErrRateLimitExceeded is returned when rate limit is exceeded
	ErrRateLimitExceeded = errors.New("rate limit exceeded")

	// ErrInvalidRequest is returned when the request is malformed
	ErrInvalidRequest = &OAuthError{ErrorType: "invalid_request", Description: "Invalid request"}

	// ErrUnsupportedGrantType is returned when the grant type is not supported
	ErrUnsupportedGrantType = &OAuthError{ErrorType: "unsupported_grant_type", Description: "Unsupported grant type"}
)

// OAuthErrorResponse represents an OAuth 2.0 error response
type OAuthErrorResponse struct {
	Error       string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

// OAuthError represents an OAuth 2.0 error
type OAuthError struct {
	ErrorType   string
	Description string
}

// Error implements the error interface
func (e *OAuthError) Error() string {
	if e.Description != "" {
		return e.ErrorType + ": " + e.Description
	}
	return e.ErrorType
}

// WithDescription returns a copy of the error with a new description
func (e *OAuthError) WithDescription(description string) *OAuthError {
	return &OAuthError{
		ErrorType:   e.ErrorType,
		Description: description,
	}
}

// ToResponseObject converts the error to a response object
func (e *OAuthError) ToResponseObject() OAuthErrorResponse {
	return OAuthErrorResponse{
		Error:       e.ErrorType,
		Description: e.Description,
	}
}

// NewOAuthErrorResponse creates a new OAuth error response
func NewOAuthErrorResponse(err error) OAuthErrorResponse {
	if oauthErr, ok := err.(*OAuthError); ok {
		return oauthErr.ToResponseObject()
	}

	switch err {
	case ErrClientNotFound:
		return OAuthErrorResponse{
			Error:       "invalid_client",
			Description: "Client not found",
		}
	case ErrClientSecretExpired:
		return OAuthErrorResponse{
			Error:       "invalid_client",
			Description: "Client secret has expired",
		}
	case ErrInvalidClientMetadata:
		return OAuthErrorResponse{
			Error:       "invalid_client_metadata",
			Description: "Invalid client metadata",
		}
	case ErrMissingRedirectURIs:
		return OAuthErrorResponse{
			Error:       "invalid_redirect_uri",
			Description: "redirect_uris is required",
		}
	case ErrRateLimitExceeded:
		return OAuthErrorResponse{
			Error:       "access_denied",
			Description: "Rate limit exceeded",
		}
	default:
		return OAuthErrorResponse{
			Error:       "server_error",
			Description: "Internal server error",
		}
	}
}
