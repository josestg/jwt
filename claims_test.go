package jwt_test

import (
	"encoding/json"
	"fmt"
	"github.com/josestg/jwt"
	"reflect"
	"testing"
	"time"
)

func TestRegisteredClaims_Valid(t *testing.T) {
	fixedTime := time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC)
	fixedTimeOneHourLater := fixedTime.Add(time.Hour)
	fixedTimeOneHourEarlier := fixedTime.Add(-time.Hour)

	tableTests := []struct {
		name       string
		claims     jwt.Claims
		validateAt time.Time
		expErr     error
	}{
		{
			name:       "given an empty RegisteredClaims, expect no error",
			expErr:     nil,
			validateAt: fixedTime,
			claims:     &jwt.RegisteredClaims{},
		},
		{
			name:       "given a RegisteredClaims with no expiration time, no before time, and no issued at time, expect no error",
			expErr:     nil,
			validateAt: fixedTime,
			claims: &jwt.RegisteredClaims{
				JWTID:          "abc123",
				Issuer:         "JWT Service",
				Subject:        "josestg",
				Audience:       []string{"https://josestg.com"},
				ExpirationTime: 0,
				NotBefore:      0,
				IssuedAt:       0,
			},
		},
		{
			name:       "given a RegisteredClaims with an expiration time in the future, no before time, and no issued at time, expect no error",
			expErr:     nil,
			validateAt: fixedTime,
			claims: &jwt.RegisteredClaims{
				JWTID:          "abc123",
				Issuer:         "JWT Service",
				Subject:        "josestg",
				Audience:       []string{"https://josestg.com"},
				ExpirationTime: jwt.NumericDateOf(fixedTimeOneHourLater),
				NotBefore:      0,
				IssuedAt:       0,
			},
		},
		{
			name:       "given a RegisteredClaims with an expiration time in the past, no before time, and no issued at time, expect an error",
			expErr:     jwt.ErrExpired,
			validateAt: fixedTime,
			claims: &jwt.RegisteredClaims{
				JWTID:          "abc123",
				Issuer:         "JWT Service",
				Subject:        "josestg",
				Audience:       []string{"https://josestg.com"},
				ExpirationTime: jwt.NumericDateOf(fixedTimeOneHourEarlier),
				NotBefore:      0,
				IssuedAt:       0,
			},
		},
		{
			name:       "given a RegisteredClaims with no expiration time, a before time in the future, and no issued at time, expect an error",
			expErr:     jwt.ErrNotValidYet,
			validateAt: fixedTime,
			claims: &jwt.RegisteredClaims{
				JWTID:          "abc123",
				Issuer:         "JWT Service",
				Subject:        "josestg",
				Audience:       []string{"https://josestg.com"},
				ExpirationTime: 0,
				NotBefore:      jwt.NumericDateOf(fixedTimeOneHourLater),
				IssuedAt:       0,
			},
		},
		{
			name:       "given a RegisteredClaims with no expiration time, a before time in the past, and no issued at time, expect no error",
			expErr:     nil,
			validateAt: fixedTime,
			claims: &jwt.RegisteredClaims{
				JWTID:          "abc123",
				Issuer:         "JWT Service",
				Subject:        "josestg",
				Audience:       []string{"https://josestg.com"},
				ExpirationTime: 0,
				NotBefore:      jwt.NumericDateOf(fixedTimeOneHourEarlier),
				IssuedAt:       0,
			},
		},
		{
			name:       "given a RegisteredClaims with no expiration time, no before time, and an issued at time in the future, expect an error",
			expErr:     jwt.ErrNotValidYet,
			validateAt: fixedTime,
			claims: &jwt.RegisteredClaims{
				JWTID:          "abc123",
				Issuer:         "JWT Service",
				Subject:        "josestg",
				Audience:       []string{"https://josestg.com"},
				ExpirationTime: 0,
				NotBefore:      jwt.NumericDateOf(fixedTimeOneHourLater),
				IssuedAt:       0,
			},
		},
		{
			name:       "given a RegisteredClaims with no expiration time, no before time, and an issued at time in the past, expect no error",
			expErr:     nil,
			validateAt: fixedTime,
			claims: &jwt.RegisteredClaims{
				JWTID:          "abc123",
				Issuer:         "JWT Service",
				Subject:        "josestg",
				Audience:       []string{"https://josestg.com"},
				ExpirationTime: 0,
				NotBefore:      jwt.NumericDateOf(fixedTimeOneHourEarlier),
				IssuedAt:       0,
			},
		},
		{
			name:       "given a RegisteredClaims with an expiration time in the future, a before time in the past, and an issued at time in the past, expect no error",
			expErr:     nil,
			validateAt: fixedTime,
			claims: &jwt.RegisteredClaims{
				Issuer:         "JWT Service",
				Subject:        "josestg",
				Audience:       []string{"https://josestg.com"},
				ExpirationTime: jwt.NumericDateOf(fixedTimeOneHourLater),
				NotBefore:      jwt.NumericDateOf(fixedTimeOneHourEarlier),
				IssuedAt:       jwt.NumericDateOf(fixedTimeOneHourEarlier),
				JWTID:          "abc123",
			},
		},
		{
			name:       "given a RegisteredClaims with an expiration time in the future, a before time in the past, and an issued at time in the future, expect an error",
			expErr:     jwt.ErrNotValidYet,
			validateAt: fixedTime,
			claims: &jwt.RegisteredClaims{
				Issuer:         "JWT Service",
				Subject:        "josestg",
				Audience:       []string{"https://josestg.com"},
				ExpirationTime: jwt.NumericDateOf(fixedTimeOneHourLater),
				NotBefore:      jwt.NumericDateOf(fixedTimeOneHourEarlier),
				IssuedAt:       jwt.NumericDateOf(fixedTimeOneHourLater),
				JWTID:          "abc123",
			},
		},
	}

	for _, tt := range tableTests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			err := tt.claims.Valid(jwt.NumericDateOf(tt.validateAt))
			if err != tt.expErr {
				t.Errorf("expected error %v; got %v", tt.expErr, err)
			}
		})
	}
}

func TestRegisteredClaims_MarshalJSON(t *testing.T) {
	fixedTime := time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC)
	fixedTimeOneHourLater := fixedTime.Add(time.Hour)
	fixedTimeOneHourEarlier := fixedTime.Add(-time.Hour)

	tableTests := []struct {
		name   string
		claims *jwt.RegisteredClaims
	}{
		{
			name: "given a RegisteredClaims with all fields set, expect a JSON string with all fields",
			claims: &jwt.RegisteredClaims{
				Issuer:         "JWT Service",
				Subject:        "josestg",
				Audience:       []string{"https://josestg.com"},
				ExpirationTime: jwt.NumericDateOf(fixedTimeOneHourLater),
				NotBefore:      jwt.NumericDateOf(fixedTimeOneHourEarlier),
				IssuedAt:       jwt.NumericDateOf(fixedTimeOneHourEarlier),
				JWTID:          "abc123",
			},
		},
		{
			name:   "given a RegisteredClaims with no fields set, expect a JSON string with no fields",
			claims: &jwt.RegisteredClaims{},
		},
	}

	for _, tt := range tableTests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			marshal, err := json.Marshal(tt.claims)
			if err != nil {
				t.Errorf("expected no error; got %v", err)
			}

			var claims jwt.RegisteredClaims
			if err := json.Unmarshal(marshal, &claims); err != nil {
				t.Errorf("expected no error; got %v", err)
			}

			t.Logf("marshaled  : %s", marshal)
			t.Logf("unmarshaled: %+v", claims)
			if !reflect.DeepEqual(claims, *tt.claims) {
				t.Errorf("expected claims to be equal; got %+v", claims)
			}
		})
	}
}

func TestRegisteredClaims_UnmarshalJSON(t *testing.T) {
	claimsWithDisallowedFields := []byte(`{"xxx": "JWT Service"}`)

	err := json.Unmarshal(claimsWithDisallowedFields, &jwt.RegisteredClaims{})
	if err == nil {
		t.Errorf("expected error; got nil")
	}

	claimsWithInvalidFields := []byte(`{"iss": 123}`)
	err = json.Unmarshal(claimsWithInvalidFields, &jwt.RegisteredClaims{})
	if err == nil {
		t.Errorf("expected error; got nil")
	}
}

func TestNumericDate_MarshalJSON(t *testing.T) {
	fixedTime := time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC)
	zeroTime := time.Time{}

	// time with nanoseconds is not zero.
	fixedTimeWithNanoseconds := fixedTime.Add(14 * time.Nanosecond)

	// time with different location will force to UTC.
	fixedTimeWithDifferentLocation := fixedTime.In(time.FixedZone("UTC+1", 3600))

	tableTests := []struct {
		name       string
		numeric    jwt.NumericDate
		expJSONStr string
	}{
		{
			name:       "given a NumericDate with a time, expect a JSON string with the time",
			numeric:    jwt.NumericDateOf(fixedTime),
			expJSONStr: fmt.Sprintf("%d", fixedTime.Unix()),
		},
		{
			name:       "given a NumericDate with no time, expect a JSON string with null",
			numeric:    jwt.NumericDateOf(time.Time{}),
			expJSONStr: fmt.Sprintf("%d", zeroTime.Unix()),
		},
		{
			name:       "given a NumericDate with a time with nanoseconds, expect a JSON string with the time truncated to seconds",
			numeric:    jwt.NumericDateOf(fixedTimeWithNanoseconds),
			expJSONStr: fmt.Sprintf("%d", fixedTime.Unix()),
		},
		{
			name:       "given a NumericDate with a time with a different location, expect a JSON string with the time in UTC",
			numeric:    jwt.NumericDateOf(fixedTimeWithDifferentLocation),
			expJSONStr: fmt.Sprintf("%d", fixedTime.Unix()),
		},
	}

	for _, tt := range tableTests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			marshal, err := json.Marshal(tt.numeric)
			if err != nil {
				t.Errorf("expected no error; got %v", err)
			}

			if string(marshal) != tt.expJSONStr {
				t.Errorf("expected JSON string %s; got %s", tt.expJSONStr, string(marshal))
			}
		})
	}
}

func TestNumericDate_UnmarshalJSON(t *testing.T) {
	fixedTime := time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC)
	zeroTime := time.Time{}

	tableTests := []struct {
		name       string
		jsonStr    string
		expNumeric jwt.NumericDate
		wantErr    bool
	}{
		{
			name:       "given a JSON string with a time, expect a NumericDate with the time",
			jsonStr:    fmt.Sprintf("%d", fixedTime.Unix()),
			expNumeric: jwt.NumericDateOf(fixedTime),
		},
		{
			name:       "given a JSON string with null, expect a NumericDate with no time",
			jsonStr:    fmt.Sprintf("%d", zeroTime.Unix()),
			expNumeric: jwt.NumericDateOf(time.Time{}),
		},
		{
			name:       "given a JSON string with a string, expect an error",
			jsonStr:    `"2022-01-01T00:00:00Z"`,
			expNumeric: jwt.NumericDateOf(time.Time{}),
			wantErr:    true,
		},
	}

	for _, tt := range tableTests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			var numeric jwt.NumericDate
			if err := json.Unmarshal([]byte(tt.jsonStr), &numeric); (err != nil) != tt.wantErr {
				t.Errorf("expected error %v; got %v", tt.wantErr, err)
			}

			if numeric != tt.expNumeric {
				t.Errorf("expected NumericDate to be %v; got %v", tt.expNumeric, numeric)
			}
		})
	}

}
