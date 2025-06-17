package jwk

import (
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/golang-jwt/jwt/v4"
)

type TokenValidator struct {
	token string
	jwks  *JWKResponse
}

// New creates a new TokenValidator with pre-fetched JWKs.
func New(token string, jwks *JWKResponse) *TokenValidator {
	return &TokenValidator{
		token: token,
		jwks:  jwks,
	}
}

// Validate validates the token using the pre-fetched JWKs and prints all claims.
func (tv *TokenValidator) Validate() (map[string]string, error) {
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		// Extract alg and kid from the token header
		alg, ok := token.Header["alg"].(string)
		if !ok {
			return nil, errors.New("missing or invalid 'alg' in token header")
		}
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, errors.New("missing or invalid 'kid' in token header")
		}

		// Ensure the algorithm matches expected method
		if token.Method.Alg() != alg {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Method.Alg())
		}

		// Find the matching key by KID
		for _, key := range tv.jwks.Keys {
			if key.KID == kid {
				pubKey, err := parseRSAPublicKey(key.N, key.E)
				if err != nil {
					return nil, fmt.Errorf("failed to parse JWK: %w", err)
				}
				return pubKey, nil
			}
		}

		return nil, fmt.Errorf("no matching key found for kid: %s", kid)
	}

	// Parse and validate
	token, err := jwt.Parse(tv.token, keyFunc)
	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	// Get Claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token claims")
	}

	return FlattenMap(claims), nil
}

// parseRSAPublicKey parses the modulus and exponent from the JWK
// and returns an RSA public key.
func parseRSAPublicKey(nStr, eStr string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, err
	}

	// Convert exponent bytes to int
	eInt := 0
	for _, b := range eBytes {
		eInt = eInt<<8 + int(b)
	}
	if eInt == 0 {
		return nil, errors.New("invalid exponent")
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: eInt,
	}, nil
}

// FlattenMap flattens a nested map into a single-level map with dot-separated
// keys.
func FlattenMap(input map[string]interface{}) map[string]string {
	flat := make(map[string]string)
	flattenRecursive("", input, flat)
	return flat
}

// flattenRecursive is a helper function that recursively flattens the map.
func flattenRecursive(prefix string, input interface{}, out map[string]string) {
	switch val := input.(type) {
	case map[string]interface{}:
		for k, v := range val {
			fullKey := k
			if prefix != "" {
				fullKey = prefix + "." + k
			}
			flattenRecursive(fullKey, v, out)
		}
	case []interface{}:
		// Join list into comma-separated string
		var items []string
		for _, item := range val {
			items = append(items, fmt.Sprintf("%v", item))
		}
		out[prefix] = strings.Join(items, ",")
	default:
		out[prefix] = fmt.Sprintf("%v", val)
	}
}
