package jwk

type JWKResponse struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	KID     string   `json:"kid"`
	KTY     string   `json:"kty"`
	ALG     string   `json:"alg"`
	USE     string   `json:"use"`
	X5C     []string `json:"x5c"`
	X5T     string   `json:"x5t"`
	X5TS256 string   `json:"x5t#S256"`
	N       string   `json:"n"`
	E       string   `json:"e"`
}
