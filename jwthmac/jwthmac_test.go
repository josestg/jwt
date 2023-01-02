package jwthmac_test

import (
	"crypto"
	"github.com/josestg/jwt/jwthmac"
	"testing"
)

func TestNewHMAC(t *testing.T) {
	const key = "key-1234"
	const msg = "this is a plain text message, it will be signed and verified"

	alg := jwthmac.NewHMAC([]byte(key), crypto.SHA256)

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
