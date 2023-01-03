package jwtrepo_test

import (
	"github.com/josestg/jwt"
	"github.com/josestg/jwt/jwtrepo"
	"testing"
)

func TestNewRoundRobin(t *testing.T) {
	rr := jwtrepo.NewRoundRobin()

	hmac1 := mockSignerVerifier("hmac-1")
	hmac2 := mockSignerVerifier("hmac-2")
	hmac3 := mockSignerVerifier("hmac-3")

	rsa1 := mockSignerVerifier("rsa-1")
	rsa2 := mockSignerVerifier("rsa-2")

	ec1 := mockSignerVerifier("ec-1")

	rr.Register(jwt.HS256, "kid-1", hmac1)
	rr.Register(jwt.HS256, "kid-2", hmac2)
	rr.Register(jwt.HS256, "kid-3", hmac3)

	rr.Register(jwt.RS256, "kid-1", rsa1)
	rr.Register(jwt.RS256, "kid-2", rsa2)

	rr.Register(jwt.ES256, "kid-1", ec1)

	expectedHmacSigners := []jwt.SignVerifier{hmac1, hmac2, hmac3, hmac1, hmac2}
	expectedRsaSigners := []jwt.SignVerifier{rsa1, rsa2, rsa1, rsa2, rsa1}
	expectedEcSigners := []jwt.SignVerifier{ec1, ec1, ec1, ec1, ec1}

	for _, alg := range []jwt.Algorithm{jwt.HS256, jwt.RS256, jwt.ES256} {
		for i := 0; i < 5; i++ {
			kid, signer, err := rr.Signer(alg)
			if err != nil {
				t.Errorf("error getting signer: %v", err)
			}

			verifier, err := rr.Verifier(alg, kid)
			if err != nil {
				t.Errorf("error getting verifier: %v", err)
			}

			switch alg {
			case jwt.HS256:
				if signer != expectedHmacSigners[i] {
					t.Errorf("expected %v; got %v", expectedHmacSigners[i], signer)
				}

				if verifier != expectedHmacSigners[i] {
					t.Errorf("expected %v; got %v", expectedHmacSigners[i], verifier)
				}
			case jwt.RS256:
				if signer != expectedRsaSigners[i] {
					t.Errorf("expected %v; got %v", expectedRsaSigners[i], signer)
				}

				if verifier != expectedRsaSigners[i] {
					t.Errorf("expected %v; got %v", expectedRsaSigners[i], verifier)
				}
			case jwt.ES256:
				if signer != expectedEcSigners[i] {
					t.Errorf("expected %v; got %v", expectedEcSigners[i], signer)
				}

				if verifier != expectedEcSigners[i] {
					t.Errorf("expected %v; got %v", expectedEcSigners[i], verifier)
				}
			}

		}
	}

	// try to get a signer for an algorithm that is not registered
	_, _, err := rr.Signer("not-registered")
	if err != jwt.ErrAlgorithmNotRegistered {
		t.Errorf("expected ErrAlgorithmNotRegistered; got %v", err)
	}

	// try to get a verifier for an algorithm that is not registered
	_, err = rr.Verifier("not-registered", "kid")
	if err != jwt.ErrAlgorithmNotRegistered {
		t.Errorf("expected ErrAlgorithmNotRegistered; got %v", err)
	}

	// try to get a verifier for a kid that is not registered
	_, err = rr.Verifier(jwt.HS256, "not-registered")
	if err != jwt.ErrMissingKID {
		t.Errorf("expected ErrMissingKID; got %v", err)
	}
}

type fakeSignerVerifier struct {
	name string
}

func mockSignerVerifier(name string) jwt.SignVerifier {
	return &fakeSignerVerifier{name}
}

func (f *fakeSignerVerifier) Sign(_ []byte) ([]byte, error) { return nil, nil }
func (f *fakeSignerVerifier) Verify(_, _ []byte) error      { return nil }
