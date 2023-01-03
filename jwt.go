package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

var (
	ErrAlgorithmNotRegistered = errors.New("algorithm not registered")
	ErrMissingKID             = errors.New("key not found")
	ErrInvalidSignature       = errors.New("invalid signature")
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
func (t *Token) Sign(r SignerRepository) (SignedToken, error) {
	kid, signer, err := r.Signer(t.Header.Algorithm)
	if err != nil {
		return SignedToken{}, err
	}

	t.Header.KeyID = kid
	headerChunk, err := encodeChunk(t.Header)
	if err != nil {
		return SignedToken{}, fmt.Errorf("encode header: %w", err)
	}

	claimsChunk, err := encodeChunk(t.Claims)
	if err != nil {
		return SignedToken{}, fmt.Errorf("encode claims: %w", err)
	}

	msg := headerChunk + "." + claimsChunk
	sig, err := signer.Sign([]byte(msg))
	if err != nil {
		return SignedToken{}, fmt.Errorf("sign: %w", err)
	}

	signed := SignedToken{
		Token:     *t,
		content:   msg,
		signature: encodeSignature(sig),
	}

	return signed, nil
}

// SignedToken represents a JWT Object with the signature.
type SignedToken struct {
	Token
	content   string
	signature string
}

// Verify verifies the signature of the token using the given verifier repository.
func (s SignedToken) Verify(r VerifierRepository) error {
	verifier, err := r.Verifier(s.Header.Algorithm, s.Header.KeyID)
	if err != nil {
		return fmt.Errorf("get verifier: %w", err)
	}

	return verifier.Verify([]byte(s.content), []byte(s.signature))
}

// String returns the JWT string representation of the token.
func (s SignedToken) String() string {
	return s.content + "." + s.signature
}

// ParsedToken is a result of parsing a JWT string.
type ParsedToken[T Claims] struct {
	Header    Header
	Claims    T
	content   string
	signature string
}

// Verify verifies the signature of the token using the given verifier repository.
func (p ParsedToken[T]) Verify(r VerifierRepository) error {
	sig := SignedToken{
		Token: Token{
			Header: p.Header,
			Claims: p.Claims,
		},
		content:   p.content,
		signature: p.signature,
	}

	return sig.Verify(r)
}

// auxPointerClaims is a helper type to get create a pointer type of T, and
// make as Claims implementation.
type auxPointerClaims[T any] interface {
	*T     // embed the pointer to the claims
	Claims // embed the claims
}

// Parse parses the given JWT string and returns a ParsedToken.
// C can be any type that implements Claims and is not a pointer.
// ptr is an auxiliary pointer to the type C, this type is not provided
// by user, it will be created internally.
func Parse[C any, ptr auxPointerClaims[C]](rawToken string) (ParsedToken[ptr], error) {
	var pt ParsedToken[ptr]
	chunks := strings.SplitN(rawToken, ".", 3)
	if len(chunks) != 3 {
		return pt, fmt.Errorf("invalid token format")
	}

	var header Header
	if err := decodeChunk(chunks[0], &header); err != nil {
		return pt, fmt.Errorf("decode header: %w", err)
	}

	// this is a hack to create a pointer to the type C,
	// and we can use it to decode the claims.
	var claims ptr = new(C)
	if err := decodeChunk(chunks[1], claims); err != nil {
		return pt, fmt.Errorf("decode claims: %w", err)
	}

	signature, err := decodeSignature(chunks[2])
	if err != nil {
		return pt, fmt.Errorf("decode signature: %w", err)
	}

	pt.Header = header
	pt.Claims = claims
	pt.content = chunks[0] + "." + chunks[1]
	pt.signature = string(signature)
	return pt, nil
}

// decodeChunk decodes the given chunk of the JWT string into the given value.
// Chunk is the part of the JWT that separated by dots.
// To decode the Signature chunk, use decodeSignature.
func decodeChunk(chunk string, dest any) error {
	r := base64.NewDecoder(base64.RawURLEncoding, strings.NewReader(chunk))
	return json.NewDecoder(r).Decode(dest)
}

// encodeChunk encodes the given value into a chunk of the JWT string.
// Chunk is the part of the JWT that separated by dots.
func encodeChunk(val any) (string, error) {
	marshal, err := json.Marshal(val)
	return base64.RawURLEncoding.EncodeToString(marshal), err
}

// encodeSignature encodes the given signature into a JWT chunk.
func encodeSignature(sig []byte) string { return base64.RawURLEncoding.EncodeToString(sig) }

// decodeSignature decodes the given signature chunk into a signature.
func decodeSignature(sig string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(sig) }
