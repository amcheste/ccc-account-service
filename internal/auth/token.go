package auth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Issuer and Audience identify CCC access tokens; both are fixed
// platform-wide (design §4).
const (
	Issuer   = "ccc-account"
	Audience = "ccc"

	// DefaultAccessTokenTTL bounds the revocation window; access
	// tokens are never denylisted (design §4).
	DefaultAccessTokenTTL = 10 * time.Minute
)

// ErrInvalidToken wraps all verification failures.
var ErrInvalidToken = errors.New("auth: invalid token")

// Claims is the access-token payload other services consume.
type Claims struct {
	jwt.RegisteredClaims
	PreferredUsername string   `json:"preferred_username"`
	Roles             []string `json:"roles"`
}

// TokenIssuer mints and verifies Ed25519 access tokens.
type TokenIssuer struct {
	private ed25519.PrivateKey
	public  ed25519.PublicKey
	kid     string
	ttl     time.Duration
}

// NewTokenIssuer builds an issuer from a 32-byte Ed25519 seed
// (delivered base64-encoded in a k8s Secret). ttl <= 0 uses the
// default.
func NewTokenIssuer(seed []byte, ttl time.Duration) (*TokenIssuer, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("auth: signing seed must be %d bytes, got %d",
			ed25519.SeedSize, len(seed))
	}
	if ttl <= 0 {
		ttl = DefaultAccessTokenTTL
	}
	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)
	sum := sha256.Sum256(public)
	return &TokenIssuer{
		private: private,
		public:  public,
		kid:     base64.RawURLEncoding.EncodeToString(sum[:8]),
		ttl:     ttl,
	}, nil
}

// ParseSigningSeed decodes a base64 (std or url, padded or raw)
// Ed25519 seed from configuration.
func ParseSigningSeed(encoded string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(encoded); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("auth: signing seed is not valid base64")
}

// Mint issues an access token for the user.
func (t *TokenIssuer) Mint(userID uuid.UUID, username string, roles []string, now time.Time) (string, error) {
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    Issuer,
			Audience:  jwt.ClaimStrings{Audience},
			Subject:   userID.String(),
			ID:        uuid.NewString(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(t.ttl)),
		},
		PreferredUsername: username,
		Roles:             roles,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tok.Header["kid"] = t.kid
	signed, err := tok.SignedString(t.private)
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}
	return signed, nil
}

// Verify checks signature, expiry, issuer, and audience.
func (t *TokenIssuer) Verify(token string) (Claims, error) {
	var claims Claims
	_, err := jwt.ParseWithClaims(token, &claims,
		func(*jwt.Token) (any, error) { return t.public, nil },
		jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
		jwt.WithIssuer(Issuer),
		jwt.WithAudience(Audience),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return Claims{}, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}
	return claims, nil
}

// JWK is one JSON Web Key; JWKS is the published set.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
}

// JWKS is the /.well-known/jwks.json document other services fetch to
// verify tokens locally without calling ValidateToken (design §3).
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWKS returns the public key set. Rotation later means appending the
// new key while old tokens remain verifiable (design §4).
func (t *TokenIssuer) JWKS() JWKS {
	return JWKS{Keys: []JWK{{
		Kty: "OKP",
		Crv: "Ed25519",
		X:   base64.RawURLEncoding.EncodeToString(t.public),
		Kid: t.kid,
		Use: "sig",
		Alg: "EdDSA",
	}}}
}
