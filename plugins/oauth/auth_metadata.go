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
	metadata := Metadata{
		Issuer:                            issuer.String(),
		AuthorizationEndpoint:             (&url.URL{Scheme: issuer.Scheme, Host: issuer.Host, Path: authorizationEndpoint}).String(),
		ResponseTypesSupported:            []string{"code"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		TokenEndpoint:                     (&url.URL{Scheme: issuer.Scheme, Host: issuer.Host, Path: tokenEndpoint}).String(),
		TokenEndpointAuthMethodsSupported: []string{"client_secret_post"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
	}

	// Add registration endpoint if provided
	if registrationEndpoint != "" {
		metadata.RegistrationEndpoint = (&url.URL{Scheme: issuer.Scheme, Host: issuer.Host, Path: registrationEndpoint}).String()
	}

	return metadata
}
