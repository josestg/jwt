package jwthmac

import (
	"crypto"
	"crypto/hmac"
	"fmt"
)

// HMAC is a HMAC signer.
// It implements both Signer and Verifier interfaces.
type HMAC struct {
	key  []byte
	hash crypto.Hash
}

// NewHMAC creates a new HMAC signer.
func NewHMAC(key []byte, hash crypto.Hash) *HMAC {
	return &HMAC{
		key:  key,
		hash: hash,
	}
}

func (h *HMAC) Verify(msg []byte, sig []byte) error {
	// we can ignore the error, it will always be nil.
	computed, _ := h.Sign(msg)
	if !hmac.Equal(computed, sig) {
		return fmt.Errorf("invalid signature")
	}
	return nil
}

func (h *HMAC) Sign(msg []byte) ([]byte, error) {
	w := hmac.New(h.hash.New, h.key)
	return w.Sum(msg), nil
}
