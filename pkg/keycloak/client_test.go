package keycloak

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Vandebron/traefik-keycloak/pkg/jwk"
	"github.com/stretchr/testify/require"
)

const (
	baseURL = "/some-prefix"
)

// GetMockClient Returns a Mock Client in order to test the KeycloakClient
func GetMockClient() (
	client *KeycloakClient,
	mux *http.ServeMux,
	serverURL string,
	teardown func(),
) {
	// mux is the HTTP request multiplexer used with the test server.
	mux = http.NewServeMux()

	// We want to ensure that tests catch mistakes where the endpoint URL is
	// specified as absolute rather than relative. It only makes a difference
	// when there's a non-empty base URL path. So, use that. See issue #752.
	apiHandler := http.NewServeMux()
	apiHandler.Handle(baseURL+"/", http.StripPrefix(baseURL, mux))
	apiHandler.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})

	// server is a test HTTP server used to provide mock API responses.
	server := httptest.NewServer(apiHandler)

	// client is the GitHub client being tested and is
	// configured to use test server.
	client = New(WithHost(server.URL + baseURL + "/"))

	return client, mux, server.URL, server.Close
}

func TestKeycloakClient_GetJWK(t *testing.T) {
	assert := require.New(t)

	t.Run("successfully retrieves JWKs", func(t *testing.T) {
		client, mux, _, teardown := GetMockClient()
		defer teardown()

		mockJWK := jwk.JWKResponse{
			Keys: []jwk.JWK{
				{
					KID:     "test-key-id",
					KTY:     "RSA",
					ALG:     "RS256",
					USE:     "sig",
					X5C:     []string{"cert1"},
					X5T:     "x5t",
					X5TS256: "x5t#S256",
					N:       "modulus",
					E:       "AQAB",
				},
			},
		}
		data, err := json.Marshal(mockJWK)
		assert.NoError(err)

		mux.HandleFunc("/realms/test-realm/protocol/openid-connect/certs", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write(data)
		})

		jwks, err := client.GetJWK("test-realm")
		assert.NoError(err)
		assert.Len(jwks.Keys, 1)
		assert.Equal("test-key-id", jwks.Keys[0].KID)
	})

	t.Run("returns error on non-200 response", func(t *testing.T) {
		client, mux, _, teardown := GetMockClient()
		defer teardown()

		mux.HandleFunc("/realms/test-realm/protocol/openid-connect/certs", func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "forbidden", http.StatusForbidden)
		})

		_, err := client.GetJWK("test-realm")
		assert.Error(err)
		assert.Contains(err.Error(), "failed to get JWK: 403 Forbidden")
	})

	t.Run("returns error on malformed JSON", func(t *testing.T) {
		client, mux, _, teardown := GetMockClient()
		defer teardown()

		mux.HandleFunc("/realms/test-realm/protocol/openid-connect/certs", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"keys":[`)
		})

		_, err := client.GetJWK("test-realm")
		assert.Error(err)
		assert.Contains(err.Error(), "failed to decode JWK response")
	})

	t.Run("returns error if no keys found", func(t *testing.T) {
		client, mux, _, teardown := GetMockClient()
		defer teardown()

		data, _ := json.Marshal(jwk.JWKResponse{Keys: []jwk.JWK{}})
		mux.HandleFunc("/realms/test-realm/protocol/openid-connect/certs", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write(data)
		})

		_, err := client.GetJWK("test-realm")
		assert.Error(err)
		assert.Contains(err.Error(), "no keys found")
	})

	t.Run("returns error on request creation", func(t *testing.T) {
		client := New(WithHost("http://[::1]:NamedPort")) // malformed URL

		_, err := client.GetJWK("test-realm")
		assert.Error(err)
		assert.Contains(err.Error(), "invalid port")
	})

	t.Run("returns error on http client failure", func(t *testing.T) {
		// Create a client with a non-routable address to simulate failure
		client := New(WithHost("http://localhost:0"))

		_, err := client.GetJWK("test-realm")
		assert.Error(err)
	})
}
