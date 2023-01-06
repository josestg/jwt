package jwtrsa_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"github.com/josestg/jwt/jwtrsa"
	"testing"
)

func TestNewRSA(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Errorf("error generating private key: %v", err)
	}

	alg := jwtrsa.NewRSA(privateKey, crypto.SHA256)

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
