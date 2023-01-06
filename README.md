# JSON Web Token (JWT)

My own implementation of JWT based on the [RFC 7519](https://tools.ietf.org/html/rfc7519).

> WARNING: this is only for educational purposes, do not use it in production.


## Concepts

This package by default using key rotation to sign the token, this means multiple requests maybe signed with different keys.
For now, it's using Round-Robin algorithm to select the key, but it can be changed to any other algorithm by implementing `jwt.Repository` interface.

A `Repository` must be able to find `jwt.Signer` by given algorithm and find `jwt.Verifier` by given algorithm and key id.


## Example

```go

package main

func main() {
	rsaKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	rsaKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	ecKey1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	ecKey2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	hmac1 := jwthmac.NewHMAC([]byte("secret"), jwt.HS256.HashFunc())
	hmac2 := jwthmac.NewHMAC([]byte("private"), jwt.HS256.HashFunc())
	rsa1 := jwtrsa.NewRSA(rsaKey1, jwt.RS256.HashFunc())
	rsa2 := jwtrsa.NewRSA(rsaKey2, jwt.RS256.HashFunc())

	ecdsa1 := jwtecdsa.NewECDSA(ecKey1, jwt.ES256.HashFunc())
	ecdsa2 := jwtecdsa.NewECDSA(ecKey2, jwt.ES256.HashFunc())

	repo := jwtrepo.NewRoundRobin()
	repo.Register(jwt.HS256, "kid-hmac-1", hmac1)
	repo.Register(jwt.HS256, "kid-hmac-2", hmac2)
	repo.Register(jwt.RS256, "kid-rsa-1", rsa1)
	repo.Register(jwt.RS256, "kid-rsa-2", rsa2)
	repo.Register(jwt.ES256, "kid-ecdsa-1", ecdsa1)
	repo.Register(jwt.ES256, "kid-ecdsa-2", ecdsa2)

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

	token := jwt.NewToken(&claims, jwt.HS256)
	signedToken, err := token.Sign(repo)
	if err != nil {
		panic(err)
	}

	fmt.Println(signedToken.Header.KeyID) // should be used key id "kid-hmac-1"

	token = jwt.NewToken(&claims, jwt.HS256)
	signedToken, err = token.Sign(repo)
	if err != nil {
		panic(err)
	}

	fmt.Println(signedToken.Header.KeyID) // should be used key id "kid-hmac-2"

	token = jwt.NewToken(&claims, jwt.RS256)
	signedToken, err = token.Sign(repo)
	if err != nil {
		panic(err)
	}

	fmt.Println(signedToken.Header.KeyID) // should be used key id "kid-rsa-1"

	// Output:
	// kid-hmac-1
	// kid-hmac-2
	// kid-rsa-1
}

```
