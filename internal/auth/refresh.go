package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// NewRefreshToken generates an opaque 256-bit refresh token and the
// SHA-256 hash the store persists. The raw token exists only in the
// HttpOnly cookie; it is never stored (design §4).
func NewRefreshToken() (token string, hash []byte, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("generate refresh token: %w", err)
	}
	token = base64.RawURLEncoding.EncodeToString(raw)
	return token, HashRefreshToken(token), nil
}

// HashRefreshToken maps a presented token to its stored hash.
func HashRefreshToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}
