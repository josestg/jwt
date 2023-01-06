package jwt_test

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"github.com/josestg/jwt"
	"github.com/josestg/jwt/jwthmac"
	"github.com/josestg/jwt/jwtrepo"
	"github.com/josestg/jwt/jwtrsa"
	"reflect"
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	tableTests := []struct {
		name    string
		jwt     string
		wantErr bool
	}{
		{
			name:    "empty",
			jwt:     "",
			wantErr: true,
		},
		{
			name:    "invalid header",
			jwt:     `eyJhbGciOiJIUzI1<NOT ?/ VALID BASE-64>NiIsImN0eSI6IkpXVCIsImtpZCI6ImtpZC0yIn0.eyJpc3MiOiJKV1QgU2VydmljZSIsInN1YiI6Impvc2VzdGciLCJhdWQiOlsiaHR0cHM6Ly9qb3Nlc3RnLmNvbSJdLCJleHAiOjE2NDA5OTg4MDAsIm5iZiI6MTY0MDk5MTYwMCwiaWF0IjoxNjQwOTkxNjAwLCJqdGkiOiJhYmMxMjMifQ.ZXlKaGJHY2lPaUpJVXpJMU5pSXNJbU4wZVNJNklrcFhWQ0lzSW10cFpDSTZJbXRwWkMweUluMC5leUpwYzNNaU9pSktWMVFnVTJWeWRtbGpaU0lzSW5OMVlpSTZJbXB2YzJWemRHY2lMQ0poZFdRaU9sc2lhSFIwY0hNNkx5OXFiM05sYzNSbkxtTnZiU0pkTENKbGVIQWlPakUyTkRBNU9UZzRNREFzSW01aVppSTZNVFkwTURrNU1UWXdNQ3dpYVdGMElqb3hOalF3T1RreE5qQXdMQ0pxZEdraU9pSmhZbU14TWpNaWZRX5WeBn1MTUoXNLvgdiVFkCHguV4ZCDt77CVn68j3vRs`,
			wantErr: true,
		},
		{
			name:    "invalid claims",
			jwt:     `eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCIsImtpZCI6ImtpZC0yIn0.eyJ<?????THIS IS NOT BASE-64>pc3MiOiJKV1QgU2VydmljZSIsInN1YiI6Impvc2VzdGciLCJhdWQiOlsiaHR0cHM6Ly9qb3Nlc3RnLmNvbSJdLCJleHAiOjE2NDA5OTg4MDAsIm5iZiI6MTY0MDk5MTYwMCwiaWF0IjoxNjQwOTkxNjAwLCJqdGkiOiJhYmMxMjMifQ.ZXlKaGJHY2lPaUpJVXpJMU5pSXNJbU4wZVNJNklrcFhWQ0lzSW10cFpDSTZJbXRwWkMweUluMC5leUpwYzNNaU9pSktWMVFnVTJWeWRtbGpaU0lzSW5OMVlpSTZJbXB2YzJWemRHY2lMQ0poZFdRaU9sc2lhSFIwY0hNNkx5OXFiM05sYzNSbkxtTnZiU0pkTENKbGVIQWlPakUyTkRBNU9UZzRNREFzSW01aVppSTZNVFkwTURrNU1UWXdNQ3dpYVdGMElqb3hOalF3T1RreE5qQXdMQ0pxZEdraU9pSmhZbU14TWpNaWZRX5WeBn1MTUoXNLvgdiVFkCHguV4ZCDt77CVn68j3vRs`,
			wantErr: true,
		},
		{
			name:    "invalid signature",
			jwt:     `eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCIsImtpZCI6ImtpZC0yIn0.eyJpc3MiOiJKV1QgU2VydmljZSIsInN1YiI6Impvc2VzdGciLCJhdWQiOlsiaHR0cHM6Ly9qb3Nlc3RnLmNvbSJdLCJleHAiOjE2NDA5OTg4MDAsIm5iZiI6MTY0MDk5MTYwMCwiaWF0IjoxNjQwOTkxNjAwLCJqdGkiOiJhYmMxMjMifQ.ZXlKaGJHY2lPaUpJVXpJMU5pSXNJbU4wZVNJNklrcFhWQ0lzSW10cFpDSTZJbXRwWkMweUluMC5leUpwYzNNaU9pSktWMVFnVTJWeWRtbGpaU0lzSW5OMVlpSTZJbXB2YzJWemRHY2lMQ0poZFdRaU9sc2lhSFIwY0hNNkx5OXFiM05sYzNSbkxtTnZiU0pkTENKbGVIQWlPakUyTkRBNU9UZzRNREFzSW01aVppSTZNVFkwTURrNU1UWXdNQ3dpYVdGMElqb3hOalF3T1RreE5qQXdMQ0pxZEdraU9pSmhZbU14TWpNaWZRX5WeBn1MTUoXNLvgdiVFkCHguV4ZCDt77CVn68j3vRs-THIS-IS-NOT-???-BASE64-ENCODED`,
			wantErr: true,
		},
		{
			name:    "valid format",
			jwt:     `eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCIsImtpZCI6ImtpZC0yIn0.eyJpc3MiOiJKV1QgU2VydmljZSIsInN1YiI6Impvc2VzdGciLCJhdWQiOlsiaHR0cHM6Ly9qb3Nlc3RnLmNvbSJdLCJleHAiOjE2NDA5OTg4MDAsIm5iZiI6MTY0MDk5MTYwMCwiaWF0IjoxNjQwOTkxNjAwLCJqdGkiOiJhYmMxMjMifQ.ZXlKaGJHY2lPaUpJVXpJMU5pSXNJbU4wZVNJNklrcFhWQ0lzSW10cFpDSTZJbXRwWkMweUluMC5leUpwYzNNaU9pSktWMVFnVTJWeWRtbGpaU0lzSW5OMVlpSTZJbXB2YzJWemRHY2lMQ0poZFdRaU9sc2lhSFIwY0hNNkx5OXFiM05sYzNSbkxtTnZiU0pkTENKbGVIQWlPakUyTkRBNU9UZzRNREFzSW01aVppSTZNVFkwTURrNU1UWXdNQ3dpYVdGMElqb3hOalF3T1RreE5qQXdMQ0pxZEdraU9pSmhZbU14TWpNaWZRX5WeBn1MTUoXNLvgdiVFkCHguV4ZCDt77CVn68j3vRs`,
			wantErr: false,
		},
	}

	for _, tt := range tableTests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := jwt.Parse[jwt.RegisteredClaims](tt.jwt)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

type fakeSignVerify struct {
	signErr   error
	verifyErr error
}

func (f *fakeSignVerify) Sign(_ []byte) ([]byte, error) { return nil, f.signErr }
func (f *fakeSignVerify) Verify(_, _ []byte) error      { return f.verifyErr }

func TestToken_Sign(t *testing.T) {
	hmac1 := jwthmac.NewHMAC([]byte("secret"), jwt.HS256.HashFunc())
	hmac2 := jwthmac.NewHMAC([]byte("private"), jwt.HS256.HashFunc())

	repo := jwtrepo.NewRoundRobin()
	repo.Register(jwt.HS256, "kid-1", hmac1)
	repo.Register(jwt.HS256, "kid-2", hmac2)

	fakeSignVerifier := &fakeSignVerify{
		signErr:   errors.New("sign error"),
		verifyErr: errors.New("verify error"),
	}

	repo2 := jwtrepo.NewRoundRobin()
	repo2.Register(jwt.HS256, "kid-3", fakeSignVerifier)

	fixedTime := time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC)
	fixedTimeOneHourLater := fixedTime.Add(time.Hour)
	fixedTimeOneHourEarlier := fixedTime.Add(-time.Hour)

	claims := jwt.RegisteredClaims{
		Issuer:         "JWT Service",
		Subject:        "josestg",
		Audience:       []string{"https://josestg.com"},
		ExpirationTime: jwt.NumericDateOf(fixedTimeOneHourLater),
		NotBefore:      jwt.NumericDateOf(fixedTimeOneHourEarlier),
		IssuedAt:       jwt.NumericDateOf(fixedTimeOneHourEarlier),
		JWTID:          "abc123",
	}

	t.Run("unregistered algorithm", func(t *testing.T) {
		token := jwt.NewToken(&claims, "unregistered-algorithm")
		_, err := token.Sign(repo)
		if !errors.Is(err, jwt.ErrAlgorithmNotRegistered) {
			t.Error("NewToken() error = nil, wantErr = true")
		}
	})

	t.Run("signer failed", func(t *testing.T) {
		token := jwt.NewToken(&claims, jwt.HS256)
		_, err := token.Sign(repo2)
		if !errors.Is(err, fakeSignVerifier.signErr) {
			t.Errorf("NewToken() error = %v, wantErr = %v", err, fakeSignVerifier.signErr)
		}
	})

	t.Run("success", func(t *testing.T) {
		token := jwt.NewToken(&claims, jwt.HS256)
		_, err := token.Sign(repo)
		if err != nil {
			t.Errorf("NewToken() error = %v, wantErr = nil", err)
		}
	})
}

func TestToken_Verify(t *testing.T) {
	hmac1 := jwthmac.NewHMAC([]byte("secret"), jwt.HS256.HashFunc())
	hmac2 := jwthmac.NewHMAC([]byte("private"), jwt.HS256.HashFunc())

	repo := jwtrepo.NewRoundRobin()
	repo.Register(jwt.HS256, "kid-1", hmac1)
	repo.Register(jwt.HS256, "kid-2", hmac2)

	const (
		jwtKID0 = `eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCIsImtpZCI6ImtpZC0wIn0.eyJpc3MiOiJKV1QgU2VydmljZSIsInN1YiI6Impvc2VzdGciLCJhdWQiOlsiaHR0cHM6Ly9qb3Nlc3RnLmNvbSJdLCJleHAiOjE2NDA5OTg4MDAsIm5iZiI6MTY0MDk5MTYwMCwiaWF0IjoxNjQwOTkxNjAwLCJqdGkiOiJhYmMxMjMifQ.ZXlKaGJHY2lPaUpJVXpJMU5pSXNJbU4wZVNJNklrcFhWQ0lzSW10cFpDSTZJbXRwWkMwd0luMC5leUpwYzNNaU9pSktWMVFnVTJWeWRtbGpaU0lzSW5OMVlpSTZJbXB2YzJWemRHY2lMQ0poZFdRaU9sc2lhSFIwY0hNNkx5OXFiM05sYzNSbkxtTnZiU0pkTENKbGVIQWlPakUyTkRBNU9UZzRNREFzSW01aVppSTZNVFkwTURrNU1UWXdNQ3dpYVdGMElqb3hOalF3T1RreE5qQXdMQ0pxZEdraU9pSmhZbU14TWpNaWZRJy7s7u6DK3TXJeN03XRutVntI02uIBKiTvmJTwizHNw`
		jwtKID1 = `eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCIsImtpZCI6ImtpZC0xIn0.eyJpc3MiOiJKV1QgU2VydmljZSIsInN1YiI6Impvc2VzdGciLCJhdWQiOlsiaHR0cHM6Ly9qb3Nlc3RnLmNvbSJdLCJleHAiOjE2NDA5OTg4MDAsIm5iZiI6MTY0MDk5MTYwMCwiaWF0IjoxNjQwOTkxNjAwLCJqdGkiOiJhYmMxMjMifQ.ZXlKaGJHY2lPaUpJVXpJMU5pSXNJbU4wZVNJNklrcFhWQ0lzSW10cFpDSTZJbXRwWkMweEluMC5leUpwYzNNaU9pSktWMVFnVTJWeWRtbGpaU0lzSW5OMVlpSTZJbXB2YzJWemRHY2lMQ0poZFdRaU9sc2lhSFIwY0hNNkx5OXFiM05sYzNSbkxtTnZiU0pkTENKbGVIQWlPakUyTkRBNU9UZzRNREFzSW01aVppSTZNVFkwTURrNU1UWXdNQ3dpYVdGMElqb3hOalF3T1RreE5qQXdMQ0pxZEdraU9pSmhZbU14TWpNaWZR-eZuF5tnR65UEI-C-K3os8Jddv0wr95sOVgixTAZYWk`
		jwtKID2 = `eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCIsImtpZCI6ImtpZC0yIn0.eyJpc3MiOiJKV1QgU2VydmljZSIsInN1YiI6Impvc2VzdGciLCJhdWQiOlsiaHR0cHM6Ly9qb3Nlc3RnLmNvbSJdLCJleHAiOjE2NDA5OTg4MDAsIm5iZiI6MTY0MDk5MTYwMCwiaWF0IjoxNjQwOTkxNjAwLCJqdGkiOiJhYmMxMjMifQ.ZXlKaGJHY2lPaUpJVXpJMU5pSXNJbU4wZVNJNklrcFhWQ0lzSW10cFpDSTZJbXRwWkMweUluMC5leUpwYzNNaU9pSktWMVFnVTJWeWRtbGpaU0lzSW5OMVlpSTZJbXB2YzJWemRHY2lMQ0poZFdRaU9sc2lhSFIwY0hNNkx5OXFiM05sYzNSbkxtTnZiU0pkTENKbGVIQWlPakUyTkRBNU9UZzRNREFzSW01aVppSTZNVFkwTURrNU1UWXdNQ3dpYVdGMElqb3hOalF3T1RreE5qQXdMQ0pxZEdraU9pSmhZbU14TWpNaWZRX5WeBn1MTUoXNLvgdiVFkCHguV4ZCDt77CVn68j3vRs`
	)

	t.Run("verify with key 0", func(t *testing.T) {
		parsed0, err := jwt.Parse[jwt.RegisteredClaims](jwtKID0)
		if err != nil {
			t.Fatalf("failed to parse token: %v", err)
		}

		err = parsed0.Verify(repo)
		if !errors.Is(err, jwt.ErrMissingKID) {
			t.Errorf("failed to verify token: %v", err)
		}
	})

	t.Run("verify with key 1", func(t *testing.T) {
		parsed1, err := jwt.Parse[jwt.RegisteredClaims](jwtKID1)
		if err != nil {
			t.Fatalf("failed to parse token: %v", err)
		}

		err = parsed1.Verify(repo)
		if err != nil {
			t.Errorf("failed to verify token: %v", err)
		}
	})

	t.Run("verify with key 2", func(t *testing.T) {
		parsed2, err := jwt.Parse[jwt.RegisteredClaims](jwtKID2)
		if err != nil {
			t.Fatalf("failed to parse token: %v", err)
		}

		err = parsed2.Verify(repo)
		if err != nil {
			t.Errorf("failed to verify token: %v", err)
		}
	})
}

func TestToken_Sign_Parse_Verify(t *testing.T) {
	fixedTime := time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC)
	fixedTimeOneHourLater := fixedTime.Add(time.Hour)
	fixedTimeOneHourEarlier := fixedTime.Add(-time.Hour)

	claims := jwt.RegisteredClaims{
		Issuer:         "JWT Service",
		Subject:        "josestg",
		Audience:       []string{"https://josestg.com"},
		ExpirationTime: jwt.NumericDateOf(fixedTimeOneHourLater),
		NotBefore:      jwt.NumericDateOf(fixedTimeOneHourEarlier),
		IssuedAt:       jwt.NumericDateOf(fixedTimeOneHourEarlier),
		JWTID:          "abc123",
	}

	rsaKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	rsaKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	hmac1 := jwthmac.NewHMAC([]byte("secret"), jwt.HS256.HashFunc())
	hmac2 := jwthmac.NewHMAC([]byte("private"), jwt.HS256.HashFunc())
	rsa1 := jwtrsa.NewRSA(rsaKey1, jwt.RS256.HashFunc())
	rsa2 := jwtrsa.NewRSA(rsaKey2, jwt.RS256.HashFunc())

	repo1 := jwtrepo.NewRoundRobin()
	repo1.Register(jwt.HS256, "kid-hmac-1", hmac1)
	repo1.Register(jwt.HS256, "kid-hmac-2", hmac2)
	repo1.Register(jwt.RS256, "kid-rsa-1", rsa1)
	repo1.Register(jwt.RS256, "kid-rsa-2", rsa2)

	repo2 := jwtrepo.NewRoundRobin()
	repo2.Register(jwt.HS256, "kid-hmac-1", hmac2)
	repo2.Register(jwt.HS256, "kid-hmac-2", hmac1)

	for i := 0; i < 10; i++ {
		i := i
		t.Run(fmt.Sprintf("round %d", i), func(t *testing.T) {
			t.Parallel()
			for _, alg := range []jwt.Algorithm{jwt.HS256, jwt.RS256} {
				token := jwt.NewToken(&claims, alg)
				signedToken, err := token.Sign(repo1)
				if err != nil {
					t.Errorf("expected nil; got err %v", err)
				}

				parsed, err := jwt.Parse[jwt.RegisteredClaims](signedToken.String())
				if err != nil {
					t.Errorf("expected nil; got err %v", err)
				}

				err = parsed.Verify(repo1)
				if err != nil {
					t.Errorf("expected nil; got err %v", err)
				}

				equal := reflect.DeepEqual(*parsed.Claims, claims)
				if !equal {
					t.Errorf("expected %v; got %v", claims, parsed.Claims)
				}

				t.Log("--------------------")
				t.Logf("Round       : %d", i)
				t.Logf("KID         : %s", parsed.Header.KeyID)
				t.Logf("Claims      : %+v", claims)
				t.Logf("Signed      : %+v", signedToken)
				t.Logf("Parsed      : %+v", parsed)
				t.Log("--------------------")
				err = parsed.Claims.Valid(jwt.NumericDateOf(fixedTime))
				if err != nil {
					t.Errorf("expected nil; got err %v", err)
				}

				// tempered token
				err = parsed.Verify(repo2)
				if err == nil {
					t.Errorf("expected err; got nil")
				}
			}
		})
	}

}
