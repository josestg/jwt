package jwtrsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
)

// RSA is an RSA signer and verifier implementation.
type RSA struct {
	key  *rsa.PrivateKey
	hash crypto.Hash
}

// NewRSA creates a new RSA signer and verifier.
func NewRSA(key *rsa.PrivateKey, hash crypto.Hash) *RSA {
	return &RSA{
		key:  key,
		hash: hash,
	}
}

func (r *RSA) Verify(msg []byte, sig []byte) error {
	hash := r.hash.New()
	hash.Write(msg)
	sum := hash.Sum(nil)

	return rsa.VerifyPKCS1v15(&r.key.PublicKey, r.hash, sum, sig)
}

func (r *RSA) Sign(msg []byte) ([]byte, error) {
	hash := r.hash.New()

	hash.Write(msg)
	sum := hash.Sum(nil)

	return rsa.SignPKCS1v15(rand.Reader, r.key, r.hash, sum)
}
