package jwtecdsa

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"github.com/josestg/jwt"
)

// ECDSA is an ECDSA signer and verifier.
type ECDSA struct {
	key  *ecdsa.PrivateKey
	hash crypto.Hash
}

// NewECDSA returns a new instance of ECDSA.
func NewECDSA(key *ecdsa.PrivateKey, hash crypto.Hash) *ECDSA {
	return &ECDSA{key: key, hash: hash}
}

// Sign signs the given payload and returns the signature.
func (e *ECDSA) Sign(payload []byte) ([]byte, error) {
	hash := e.hash.New()
	hash.Write(payload)
	hashed := hash.Sum(nil)

	return ecdsa.SignASN1(rand.Reader, e.key, hashed)
}

// Verify verifies the given payload and signature.
func (e *ECDSA) Verify(payload, signature []byte) error {
	hash := e.hash.New()
	hash.Write(payload)
	hashed := hash.Sum(nil)

	ok := ecdsa.VerifyASN1(&e.key.PublicKey, hashed, signature)
	if !ok {
		return jwt.ErrInvalidSignature
	}

	return nil
}
