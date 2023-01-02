package jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

var (
	ErrAlgorithmNotRegistered = errors.New("algorithm not registered")
	ErrKeyNotFound            = errors.New("key not found")
)

// Signer is a cryptographic signer interface.
// This interface must be implemented by the signing algorithm,
// such as RSA, ECDSA, and HMAC.
type Signer interface {
	// Sign signs the given message and returns the signature.
	Sign(msg []byte) ([]byte, error)
}

// SignerRepository is a repository of signers.
// The repository knows to choose the right signer for the given algorithm,
// the signer is chosen depending on the implementation of the repository.
// For example, a repository could be implemented using Round-Robin scheduling,
// to rotate the signers. When a signer is chosen, the repository also returns
// the KeyID of the signer that can be used to retrieve the signer from the
// VerifierRepository.
type SignerRepository interface {
	// Signer returns the signer for the given algorithm, and which keyID it uses.
	Signer(alg Algorithm) (kid string, sig Signer, err error)
}

// Verifier is a cryptographic verifier interface.
// This interface must be implemented by the signing algorithm,
// such as RSA, ECDSA, and HMAC.
type Verifier interface {
	// Verify verifies the given message and signature.
	Verify(msg, sig []byte) error
}

// VerifierRepository is a repository of verifiers.
// The repository knows to fetch the right verifier for the given algorithm and
// keyID that was used to sign the token.
type VerifierRepository interface {
	// Verifier returns the verifier for the given algorithm and keyID.
	Verifier(alg Algorithm, kid string) (Verifier, error)
}

// Repository is a repository of signers and verifiers.
type Repository interface {
	SignerRepository
	VerifierRepository
}

// SignVerifier is a Signer and Verifier.
type SignVerifier interface {
	Signer
	Verifier
}

// Token represents a JWT Object without the signature.
// This is also referred as unsigned token.
type Token struct {
	Header Header
	Claims Claims
}

// NewToken creates a new unsigned token.
// The algorithm is used to sign to fetch the signer from the repository.
func NewToken(claims Claims, alg Algorithm) *Token {
	return &Token{
		Claims: claims,
		Header: Header{
			Algorithm:   alg,
			ContentType: JWT,
		},
	}
}

// Sign signs the token using the given signer repository.
func (t *Token) Sign(_ SignerRepository) (SignedToken, error) {
	return SignedToken{}, nil
}

// SignedToken represents a JWT Object with the signature.
type SignedToken struct {
	Token
	signature string
}

// Verify verifies the signature of the token using the given verifier repository.
func (s SignedToken) Verify(_ VerifierRepository) error {
	return nil
}

// Signature returns the signature of the token.
func (s SignedToken) Signature() string {
	return s.signature
}

// ParsedToken is a result of parsing a JWT string.
type ParsedToken[T Claims] struct {
	Header    Header
	Claims    T
	content   string
	signature string
}

// Parse parses the given JWT string and returns a ParsedToken.
func Parse[T Claims](_ string) (ParsedToken[T], error) {
	var pt ParsedToken[T]
	return pt, nil
}

// DecodeChunk decodes the given chunk of the JWT string into the given value.
// Chunk is the part of the JWT that separated by dots.
// To decode the Signature chunk, use DecodeSignature.
func DecodeChunk(chunk string, dest any) error {
	r := base64.NewDecoder(base64.RawURLEncoding, strings.NewReader(chunk))
	return json.NewDecoder(r).Decode(dest)
}

// EncodeChunk encodes the given value into a chunk of the JWT string.
// Chunk is the part of the JWT that separated by dots.
func EncodeChunk(val any) (string, error) {
	var out bytes.Buffer
	err := json.NewEncoder(base64.NewEncoder(base64.RawURLEncoding, &out)).Encode(val)
	return out.String(), err
}

// EncodeSignature encodes the given signature into a JWT chunk.
func EncodeSignature(sig []byte) string { return base64.RawURLEncoding.EncodeToString(sig) }

// DecodeSignature decodes the given signature chunk into a signature.
func DecodeSignature(sig string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(sig) }
