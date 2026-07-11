// Package auth implements the cryptographic core of the account
// service: argon2id password hashing sized for Pi-class nodes,
// Ed25519 JWT mint and verify with JWKS publication, and opaque
// refresh-token generation. Rotation *policy* (chains, reuse
// detection) lives in the service layer on top of the store.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// ErrWrongPassword is returned when verification fails.
var ErrWrongPassword = errors.New("auth: wrong password")

// Argon2Params are the argon2id cost parameters. Defaults follow the
// OWASP minimum (19 MiB, t=2, p=1), deliberately chosen for Pi 5
// hardware: roughly 40 to 80 ms per hash, bounded memory. Parameters
// are embedded in each PHC hash, so raising them later rehashes lazily
// on next login (design §4).
type Argon2Params struct {
	MemoryKiB   uint32
	Iterations  uint32
	Parallelism uint8
	SaltLen     uint32
	KeyLen      uint32
}

// DefaultParams is the production configuration.
func DefaultParams() Argon2Params {
	return Argon2Params{
		MemoryKiB:   19 * 1024,
		Iterations:  2,
		Parallelism: 1,
		SaltLen:     16,
		KeyLen:      32,
	}
}

// Hasher hashes and verifies passwords. The semaphore caps concurrent
// hashes so worst-case memory stays inside the pod limit
// (MemoryKiB x maxConcurrent, design §5).
type Hasher struct {
	params Argon2Params
	sem    chan struct{}
}

// NewHasher builds a Hasher; maxConcurrent <= 0 defaults to 4.
func NewHasher(params Argon2Params, maxConcurrent int) *Hasher {
	if maxConcurrent <= 0 {
		maxConcurrent = 4
	}
	return &Hasher{params: params, sem: make(chan struct{}, maxConcurrent)}
}

func (h *Hasher) acquire() func() {
	h.sem <- struct{}{}
	return func() { <-h.sem }
}

// Hash derives a PHC-formatted argon2id string for the password.
func (h *Hasher) Hash(password string) (string, error) {
	defer h.acquire()()

	salt := make([]byte, h.params.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt,
		h.params.Iterations, h.params.MemoryKiB, h.params.Parallelism, h.params.KeyLen)

	b64 := base64.RawStdEncoding.EncodeToString
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, h.params.MemoryKiB, h.params.Iterations,
		h.params.Parallelism, b64(salt), b64(key)), nil
}

// Verify checks password against a PHC hash. needsRehash reports that
// the stored hash uses weaker parameters than the Hasher's current
// configuration, signalling a lazy rehash on successful login.
func (h *Hasher) Verify(password, phc string) (needsRehash bool, err error) {
	defer h.acquire()()

	params, salt, key, err := parsePHC(phc)
	if err != nil {
		return false, err
	}
	keyLen := uint32(len(key)) //nolint:gosec // parsePHC bounds the key length
	candidate := argon2.IDKey([]byte(password), salt,
		params.Iterations, params.MemoryKiB, params.Parallelism, keyLen)
	if subtle.ConstantTimeCompare(candidate, key) != 1 {
		return false, ErrWrongPassword
	}
	weaker := params.MemoryKiB < h.params.MemoryKiB ||
		params.Iterations < h.params.Iterations ||
		keyLen < h.params.KeyLen
	return weaker, nil
}

func parsePHC(phc string) (Argon2Params, []byte, []byte, error) {
	var p Argon2Params
	parts := strings.Split(phc, "$")
	// "", "argon2id", "v=19", "m=...,t=...,p=...", salt, hash
	if len(parts) != 6 || parts[1] != "argon2id" {
		return p, nil, nil, errors.New("auth: malformed argon2id hash")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return p, nil, nil, errors.New("auth: unsupported argon2 version")
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d",
		&p.MemoryKiB, &p.Iterations, &p.Parallelism); err != nil {
		return p, nil, nil, errors.New("auth: malformed argon2id parameters")
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return p, nil, nil, errors.New("auth: malformed salt")
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return p, nil, nil, errors.New("auth: malformed hash")
	}
	if len(key) < 16 || len(key) > 128 {
		return p, nil, nil, errors.New("auth: implausible key length")
	}
	return p, salt, key, nil
}
