package jwt_test

import (
	"crypto"
	"github.com/josestg/jwt"
	"testing"
)

func TestHeader_Valid(t *testing.T) {
	tests := []struct {
		name string
		h    jwt.Header
		want bool
	}{
		{
			name: "empty",
			h:    jwt.Header{},
			want: false,
		},
		{
			name: "valid",
			h: jwt.Header{
				Algorithm:   "HS256",
				ContentType: "JWT",
				KeyID:       "key-id-1234",
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.h.Valid(); (got == nil) != tt.want {
				t.Errorf("Header.Valid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAlgorithm_HashFunc(t *testing.T) {
	alg := jwt.Algorithm("HS256")
	if alg.HashFunc() != crypto.SHA256 {
		t.Errorf("expected crypto.SHA256; got %v", alg.HashFunc())
	}

	alg2 := jwt.Algorithm("XX256")
	if alg2.HashFunc() != crypto.Hash(0) {
		t.Errorf("expected crypto.Hash(0); got %v", alg2.HashFunc())
	}
}

func TestAlgorithm_String(t *testing.T) {
	tests := []struct {
		name string
		alg  jwt.Algorithm
		want string
	}{
		{
			name: "empty",
			alg:  "",
			want: "",
		},
		{
			name: "HS256",
			alg:  "HS256",
			want: "HS256",
		},
		{
			name: "RS256",
			alg:  "RS256",
			want: "RS256",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.alg.String(); got != tt.want {
				t.Errorf("Algorithm.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestContentType_String(t *testing.T) {
	tests := []struct {
		name string
		ct   jwt.ContentType
		want string
	}{
		{
			name: "empty",
			ct:   "",
			want: "",
		},
		{
			name: "JWT",
			ct:   "JWT",
			want: "JWT",
		},
		{
			name: "JWE",
			ct:   "JWE",
			want: "JWE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ct.String(); got != tt.want {
				t.Errorf("ContentType.String() = %v, want %v", got, tt.want)
			}
		})
	}
}
