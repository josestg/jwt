package jwt

import (
	"crypto"
	"fmt"
)

const (
	// ES256 is the ECDSA algorithm is used elliptic curve digital signature
	// algorithm (ECDSA) and the SHA-256 hash function. The curve is chosen
	// by the implementation of the signer and verifier.
	ES256 Algorithm = "ES256"

	// HS256 is the HMAC algorithm using SHA-256 hash function.
	HS256 Algorithm = "HS256"

	// RS256 is the RSA algorithm using SHA-256 hash function.
	RS256 Algorithm = "RS256"

	// RS512 is the RSA algorithm using SHA-512 hash function.
	RS512 Algorithm = "RS512"
)

// algorithms are set of supported algorithms.
var algorithms = map[Algorithm]crypto.Hash{
	ES256: crypto.SHA256,
	HS256: crypto.SHA256,
	RS256: crypto.SHA256,
	RS512: crypto.SHA512,
}

// Algorithm is a string that represents a cryptographic algorithm.
// It is used to identify the algorithm used to sign or verify a JWT.
type Algorithm string

// HashFunc returns the hash function used by the algorithm.
// For example, ES256 returns crypto.SHA256 and RS512 returns crypto.SHA512.
func (a Algorithm) HashFunc() crypto.Hash {
	h, ok := algorithms[a]
	if !ok {
		return crypto.Hash(0)
	}

	return h
}

// String returns the string representation of the algorithm.
func (a Algorithm) String() string { return string(a) }

// ContentType is a MIME type [IANA.MediaTypes] of this complete JWT.
// link: https://tools.ietf.org/html/rfc7519#section-5.1
type ContentType string

const (
	// JWT is the default content type.
	JWT ContentType = "JWT"
	// JWE is stands for JSON Web Encryption.
	JWE ContentType = "JWE"
)

// String returns the string of the content type.
func (c ContentType) String() string { return string(c) }

// Header represents the header of a JWT.
// link: https://tools.ietf.org/html/rfc7519#section-5
type Header struct {
	// Algorithm identifies the cryptographic algorithm used to secure the JWT.
	Algorithm Algorithm `json:"alg"`

	// ContentType identifies the media type of the secured content.
	ContentType ContentType `json:"cty,omitempty"`

	// KeyID identifies the key used to secure the JWT.
	KeyID string `json:"kid,omitempty"`
}

// Valid checks if the header is valid.
// In specs, alg is not required, but here it is.
// link: https://tools.ietf.org/html/rfc7519#section-5.1
func (h Header) Valid() error {
	if _, ok := algorithms[h.Algorithm]; !ok {
		return fmt.Errorf("unsupported algorithm %s", h.Algorithm)
	}

	return nil
}
