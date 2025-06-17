package jwk

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/require"
)

func TestValidate_WithCustomClaims(t *testing.T) {
	assert := require.New(t)

	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(err)
	publicKey := privateKey.Public().(*rsa.PublicKey)

	// Base64 encode the modulus and exponent
	n := base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes())

	kid := "custom-kid"

	// Create JWK
	jwk := JWK{
		KID: kid,
		KTY: "RSA",
		ALG: "RS256",
		USE: "sig",
		N:   n,
		E:   e,
	}
	jwks := &JWKResponse{
		Keys: []JWK{jwk},
	}

	// Define custom claims
	claims := jwt.MapClaims{
		"sub":   "user123",
		"email": "test@example.com",
		"roles": []string{"admin", "user"},
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(10 * time.Minute).Unix(),
	}

	// Create token with custom claims
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid

	signedToken, err := token.SignedString(privateKey)
	assert.NoError(err)

	// Validate the token using your JWK package logic
	validator := New(signedToken, jwks)

	c, err := validator.Validate()
	assert.NoError(err)
	assert.NotNil(c)
}
