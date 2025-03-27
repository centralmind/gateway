package oauth

// OAuthClientMetadata represents the metadata for a dynamically registered OAuth client
type OAuthClientMetadata struct {
	// Required fields
	RedirectURIs []string `json:"redirect_uris"`

	// Optional fields
	ClientName              string   `json:"client_name,omitempty"`
	ClientURI               string   `json:"client_uri,omitempty"`
	LogoURI                 string   `json:"logo_uri,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	ContactsEmails          []string `json:"contacts,omitempty"`
	PolicyURI               string   `json:"policy_uri,omitempty"`
	TermsOfServiceURI       string   `json:"tos_uri,omitempty"`
	JwksURI                 string   `json:"jwks_uri,omitempty"`
	SoftwareID              string   `json:"software_id,omitempty"`
	SoftwareVersion         string   `json:"software_version,omitempty"`
}

// OAuthClientInformation represents the full client information including credentials
type OAuthClientInformation struct {
	// Fields from client metadata
	OAuthClientMetadata

	// Generated fields
	ClientID              string `json:"client_id"`
	ClientSecret          string `json:"client_secret,omitempty"`
	ClientIDIssuedAt      int64  `json:"client_id_issued_at"`
	ClientSecretExpiresAt int64  `json:"client_secret_expires_at,omitempty"`
}
