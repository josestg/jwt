package jwtecdsa_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"github.com/josestg/jwt/jwtecdsa"
	"testing"
)

func TestNewECDSA(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Errorf("error generating private key: %v", err)
	}

	alg := jwtecdsa.NewECDSA(privateKey, crypto.SHA256)

	const msg = "this is a plain text message, it will be signed and verified"

	sig, err := alg.Sign([]byte(msg))
	if err != nil {
		t.Errorf("error signing message: %v", err)
	}

	if err := alg.Verify([]byte(msg), sig); err != nil {
		t.Errorf("error verifying signature: %v", err)
	}

	// tamper with the message
	if err := alg.Verify([]byte(msg+"tampered"), sig); err == nil {
		t.Errorf("expected error verifying signature")
	}
}
