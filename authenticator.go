package authenticator

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"text/template"

	"github.com/vandebron/keycloak-config/authenticator/pkg/jwk"
	"github.com/vandebron/keycloak-config/authenticator/pkg/keycloak"
)

const (
	UnauthenticatedHeader = "X-Auth-Unauthenticated"
)

// Config the plugin configuration.
type Config struct {
	Keycloak      string   `json:"keycloak,omitempty"`
	Realm         string   `json:"realm,omitempty"`
	ExcludeClaims []string `json:"excludeClaims,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		Keycloak:      "",
		ExcludeClaims: []string{},
	}
}

// Authenticator plugin.
type Authenticator struct {
	next     http.Handler
	name     string
	kc       *keycloak.KeycloakClient
	jwks     *jwk.JWKResponse
	cfg      *Config
	template *template.Template
	realms   []string
}

// New initialises the plugin.
func New(
	ctx context.Context,
	next http.Handler,
	config *Config,
	name string,
) (http.Handler, error) {
	kc := keycloak.New(keycloak.WithHost(config.Keycloak))

	// TODO we should periodically refresh the JWKs
	jwks, err := kc.GetJWK(config.Realm)
	if err != nil {
		os.Stderr.WriteString(fmt.Sprintf("Error fetching JWKs: %v\n", err))
		return nil, err
	}

	return &Authenticator{
		next:   next,
		name:   name,
		kc:     kc,
		cfg:    config,
		jwks:   jwks,
		realms: []string{config.Realm},
	}, nil
}

// ServeHTTP is the authentication middleware that sets the
// headers for requests
func (a *Authenticator) ServeHTTP(
	w http.ResponseWriter,
	r *http.Request,
) {
	token := getAuthToken(r)

	if token == "" {
		r.Header.Set(UnauthenticatedHeader, "unauthenticated")
	}

	validator := jwk.New(
		token,
		a.jwks,
	)

	claims, err := validator.Validate()

	if claims == nil || err != nil {
		r.Header.Set(UnauthenticatedHeader, "true")
	} else {
		// Set the claims as headers
		for k, v := range claims {
			// Skip excluded claims
			if stringInList(k, a.cfg.ExcludeClaims) {
				continue
			}
			r.Header.Set(fmt.Sprintf("X-Auth-%v", k), v)
		}
	}

	a.next.ServeHTTP(w, r)
}

// getAuthToken extracts the Bearer token from the
// Authorization header.
func getAuthToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return ""
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return ""
	}

	return parts[1]
}

func stringInList(s string, list []string) bool {
	for _, item := range list {
		if s == item {
			return true
		}
	}
	return false
}
