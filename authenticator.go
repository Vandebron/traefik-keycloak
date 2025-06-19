package authenticator

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"text/template"
	"time"

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
	RefreshInterval string `json:"refreshInterval,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		Keycloak:      "",
		ExcludeClaims: []string{},
		RefreshInterval: "30m",
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
	mu       sync.RWMutex
}

// New initialises the plugin.
func New(
	ctx context.Context,
	next http.Handler,
	config *Config,
	name string,
) (http.Handler, error) {
	refreshInterval, err := time.ParseDuration(config.RefreshInterval)
	if err != nil {
		os.Stderr.WriteString(fmt.Sprintf("Error parsing refresh interval: %v\n", err))
		return nil, err
	}

	kc := keycloak.New(keycloak.WithHost(config.Keycloak))

	jwks, err := kc.GetJWK(config.Realm)
	if err != nil {
		os.Stderr.WriteString(fmt.Sprintf("Error fetching JWKs: %v\n", err))
		return nil, err
	}

	a := &Authenticator{
		next:   next,
		name:   name,
		kc:     kc,
		cfg:    config,
		jwks:   jwks,
		realms: []string{config.Realm},
	}

	a.periodicRefreshJWK(ctx, refreshInterval)

	return a, nil
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

	a.mu.RLock()
	jwks := a.jwks
	a.mu.RUnlock()

	validator := jwk.New(
		token,
		jwks,
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

// Starts a goroutine that periodically refreshes the JWKs
func (a *Authenticator) periodicRefreshJWK(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	go func() {
		for {
			select {
			case <-ticker.C:
				a.refreshJWK()
			case <-ctx.Done():
				return
			}
		}
	}()
}

// Refreshes JWKs for configured realm.
func (a *Authenticator) refreshJWK() {
	jwks, err := a.kc.GetJWK(a.cfg.Realm)
	if err != nil {
		log.Printf("Error refreshing JWKs for realm %s: %v", a.cfg.Realm, err)
		return
	}

	a.mu.Lock()
	a.jwks = jwks
	a.mu.Unlock()
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
