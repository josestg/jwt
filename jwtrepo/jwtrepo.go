package jwtrepo

import (
	"github.com/josestg/jwt"
	"sync"
)

// entry contains a key id and a signer/verifier implementation.
type entry struct {
	kid string
	imp jwt.SignVerifier
}

// entries is a slice of entry.
type entries []entry

// RoundRobin is an implementation of jwt.Repository that uses a round-robin
// algorithm to choose the signer and verifier.
type RoundRobin struct {
	mu         *sync.RWMutex
	nextPicked map[jwt.Algorithm]int
	algorithms map[jwt.Algorithm]entries
}

// NewRoundRobin returns a new instance of RoundRobin.
func NewRoundRobin() *RoundRobin {
	return &RoundRobin{
		mu:         new(sync.RWMutex),
		nextPicked: make(map[jwt.Algorithm]int),
		algorithms: make(map[jwt.Algorithm]entries),
	}
}

// Register registers a new signer/verifier implementation for the given
// algorithm and key id.
func (r *RoundRobin) Register(alg jwt.Algorithm, kid string, imp jwt.SignVerifier) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.algorithms[alg]; !ok {
		r.algorithms[alg] = make(entries, 0)
		r.nextPicked[alg] = 0
	}

	r.algorithms[alg] = append(r.algorithms[alg], entry{kid, imp})
}

// Signer returns a signer implementation for the given algorithm.
func (r *RoundRobin) Signer(alg jwt.Algorithm) (kid string, sig jwt.Signer, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	pairs, ok := r.algorithms[alg]
	if !ok {
		return "", nil, jwt.ErrAlgorithmNotRegistered
	}

	index := r.nextPicked[alg]
	r.nextPicked[alg] = (index + 1) % len(pairs)
	return pairs[index].kid, pairs[index].imp, nil
}

// Verifier returns a verifier implementation for the given algorithm and key id.
func (r *RoundRobin) Verifier(alg jwt.Algorithm, kid string) (jwt.Verifier, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	pairs, ok := r.algorithms[alg]
	if !ok {
		return nil, jwt.ErrAlgorithmNotRegistered
	}

	for _, pair := range pairs {
		if pair.kid == kid {
			return pair.imp, nil
		}
	}

	return nil, jwt.ErrKeyNotFound
}
