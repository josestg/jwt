// Package jwt implements JSON Web Token (JWT) as specified in RFC 7519.
// link: https://tools.ietf.org/html/rfc7519
package jwt

import (
	"bytes"
	"encoding/json"
	"errors"
	"time"
)

var (
	// ErrExpired indicates that the token is expired when
	// validating at a given time.
	// see: https://tools.ietf.org/html/rfc7519#section-4.1.4
	ErrExpired = errors.New("token is expired")

	// ErrNotValidYet indicates that the token is not valid yet when
	// validating at a given time.
	// see: https://tools.ietf.org/html/rfc7519#section-4.1.5
	ErrNotValidYet = errors.New("token is not valid yet")
)

// NumericDate is a JSON numeric value representing the number of seconds from
// 1970-01-01T00:00:00Z UTC until the specified UTC date/time, ignoring leap seconds.
// that is equivalent to the time.Time.Unix() in Go, to be precise, we provide the
// location as UTC.
// see: https://tools.ietf.org/html/rfc7519#section-2
type NumericDate int64

// NumericDateOf returns the NumericDate of a given time.
func NumericDateOf(t time.Time) NumericDate {
	return NumericDate(t.In(time.UTC).Unix())
}

// MarshalJSON encodes the time as JSON.
func (t NumericDate) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Unix(int64(t), 0).In(time.UTC).Unix())
}

// UnmarshalJSON decodes the time from JSON.
func (t *NumericDate) UnmarshalJSON(data []byte) error {
	var seconds int64
	if err := json.Unmarshal(data, &seconds); err != nil {
		*t = NumericDateOf(time.Time{})
		return err
	}

	*t = NumericDate(seconds)
	return nil
}

// Claims is a contract for a claims object.
// A claim is represented as a name/value pair consisting of a Claim Name and a
// Claim Value.
type Claims interface {
	// Valid checks if the claims are valid at a given time.
	Valid(at NumericDate) error
	json.Unmarshaler
	json.Marshaler
}

// auxRegisteredClaims is an auxiliary type for RegisteredClaims.
// This type must be an alias of RegisteredClaims, to avoid inherit
// MarshalJSON and UnmarshalJSON. If not, it will cause an infinite loop.
type auxRegisteredClaims RegisteredClaims

// RegisteredClaims is a claims that follows RFC 7519 Section 4.
// link: https://tools.ietf.org/html/rfc7519#section-4
type RegisteredClaims struct {
	// Issuer identifies the principal that issued the JWT.
	Issuer string `json:"iss,omitempty"`

	// Subject identifies the subject of the JWT.
	Subject string `json:"sub,omitempty"`

	// Audience identifies the recipients that the JWT is intended for.
	Audience []string `json:"aud,omitempty"`

	// ExpirationTime identifies the expiration time on or after
	// which the JWT MUST NOT be accepted for processing.
	ExpirationTime NumericDate `json:"exp,omitempty"`

	// NotBefore identifies the time before which the JWT MUST NOT
	// be accepted for processing.
	NotBefore NumericDate `json:"nbf,omitempty"`

	// IssuedAt identifies the time at which the JWT was issued.
	IssuedAt NumericDate `json:"iat,omitempty"`

	// JWTID provides a unique identifier for the JWT.
	JWTID string `json:"jti,omitempty"`
}

// Valid checks token expiration and not before at a given time.
// If any error occurs, it returns either ErrExpired or ErrNotValidYet.
func (r *RegisteredClaims) Valid(at NumericDate) error {
	if r.ExpirationTime != 0 && at > r.ExpirationTime {
		return ErrExpired
	}

	if r.NotBefore != 0 && at < r.NotBefore {
		return ErrNotValidYet
	}

	if r.IssuedAt != 0 && at < r.IssuedAt {
		return ErrNotValidYet
	}

	return nil
}

// MarshalJSON encodes the claims as JSON.
func (r *RegisteredClaims) MarshalJSON() ([]byte, error) {
	claims := auxRegisteredClaims(*r)
	return json.Marshal(claims)
}

// UnmarshalJSON decodes the claims from JSON.
func (r *RegisteredClaims) UnmarshalJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewBuffer(data))
	decoder.DisallowUnknownFields()

	var claims auxRegisteredClaims
	if err := decoder.Decode(&claims); err != nil {
		return err
	}

	*r = RegisteredClaims(claims)
	return nil
}
