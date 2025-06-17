package keycloak

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/vandebron/keycloak-config/authenticator/pkg/jwk"
)

// KeycloakClient represents a client for interacting with Keycloak.
type KeycloakClient struct {
	*http.Client

	host string
}

// option is a function that configures the Keycloak client.
type Option func(*KeycloakClient)

// WithHost sets the host for the Keycloak client.
func WithHost(h string) Option {
	return func(k *KeycloakClient) {
		k.host = h
	}
}

// New creates a new Keycloak client with the specified options.
func New(opts ...Option) *KeycloakClient {
	host := os.Getenv("KEYCLOAK_HOST")
	// by default we assume the Keycloak service is running in the same Kubernetes
	// cluster
	if host == "" {
		host = "http://keycloak.keycloak.svc.cluster.local:8080"
	}

	// Set defaults
	client := &KeycloakClient{
		Client: &http.Client{},
		host:   host,
	}

	// Apply options to the client
	for _, opt := range opts {
		opt(client)
	}

	return client
}

// GetJWK retrieves the JSON Web Key (JWK) for the specified realm.
func (kc *KeycloakClient) GetJWK(
	realm string,
) (*jwk.JWKResponse, error) {
	jwks := &jwk.JWKResponse{}
	url := kc.host + "/auth/realms/" + realm + "/protocol/openid-connect/certs"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return jwks, err
	}

	res, err := kc.Do(req)

	if err != nil {
		return jwks, err
	}

	if res.StatusCode != http.StatusOK {
		return jwks, fmt.Errorf("failed to get JWK: %s", res.Status)
	}

	defer res.Body.Close()

	if err := json.NewDecoder(res.Body).Decode(jwks); err != nil {
		return jwks, fmt.Errorf("failed to decode JWK response: %v", err)
	}
	if len(jwks.Keys) == 0 {
		return jwks, fmt.Errorf("no keys found in JWK response")
	}

	return jwks, nil
}

// Do executes a HTTP request and returns the response.
func (kc *KeycloakClient) Do(req *http.Request) (*http.Response, error) {
	return kc.Client.Do(req)
}
