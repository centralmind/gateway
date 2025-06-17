package oauth

import "net/url"

type Metadata struct {
	Issuer                            string   `json:"issuer"`
	ServiceDocumentation              *string  `json:"service_documentation,omitempty"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	RegistrationEndpoint              string   `json:"registration_endpoint,omitempty"`
}

func NewMetadata(issuer url.URL, authorizationEndpoint, tokenEndpoint string, registrationEndpoint string) Metadata {
	buildURL := func(endpoint string) string {
		if u, err := url.Parse(endpoint); err == nil && u.IsAbs() {
			return endpoint
		}
		return (&url.URL{Scheme: issuer.Scheme, Host: issuer.Host, Path: endpoint}).String()
	}

	metadata := Metadata{
		Issuer:                            issuer.String(),
		AuthorizationEndpoint:             buildURL(authorizationEndpoint),
		ResponseTypesSupported:            []string{"code"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		TokenEndpoint:                     buildURL(tokenEndpoint),
		TokenEndpointAuthMethodsSupported: []string{"client_secret_post"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
	}

	// Add registration endpoint if provided
	if registrationEndpoint != "" {
		metadata.RegistrationEndpoint = buildURL(registrationEndpoint)
	}

	return metadata
}
