package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func testIssuer(t *testing.T, ttl time.Duration) *TokenIssuer {
	t.Helper()
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	iss, err := NewTokenIssuer(seed, ttl)
	if err != nil {
		t.Fatal(err)
	}
	return iss
}

func TestMintVerifyRoundTrip(t *testing.T) {
	iss := testIssuer(t, 0)
	userID := uuid.Must(uuid.NewV7())

	token, err := iss.Mint(userID, "alan", []string{"admin"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	claims, err := iss.Verify(token)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != userID.String() {
		t.Errorf("sub = %q, want %q", claims.Subject, userID)
	}
	if claims.PreferredUsername != "alan" || len(claims.Roles) != 1 || claims.Roles[0] != "admin" {
		t.Errorf("claims = %+v", claims)
	}
	if claims.ID == "" {
		t.Error("jti missing")
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	iss := testIssuer(t, 0)
	token, _ := iss.Mint(uuid.Must(uuid.NewV7()), "sam", []string{"member"}, time.Now())

	// Swap the payload's role claim; signature must fail.
	parts := strings.Split(token, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	forged := strings.Replace(string(payload), "member", "admin", 1)
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(forged))

	if _, err := iss.Verify(strings.Join(parts, ".")); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("tampered token verified: err = %v", err)
	}
}

func TestVerifyRejectsExpired(t *testing.T) {
	iss := testIssuer(t, time.Minute)
	token, _ := iss.Mint(uuid.Must(uuid.NewV7()), "alan", nil, time.Now().Add(-2*time.Minute))
	if _, err := iss.Verify(token); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expired token verified: err = %v", err)
	}
}

func TestVerifyRejectsOtherIssuersKey(t *testing.T) {
	a, b := testIssuer(t, 0), testIssuer(t, 0)
	token, _ := a.Mint(uuid.Must(uuid.NewV7()), "alan", nil, time.Now())
	if _, err := b.Verify(token); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("foreign-key token verified: err = %v", err)
	}
}

func TestNewTokenIssuerRejectsBadSeed(t *testing.T) {
	if _, err := NewTokenIssuer(make([]byte, 16), 0); err == nil {
		t.Error("16-byte seed accepted")
	}
}

func TestParseSigningSeed(t *testing.T) {
	seed := make([]byte, 32)
	_, _ = rand.Read(seed)
	for _, enc := range []string{
		base64.StdEncoding.EncodeToString(seed),
		base64.RawURLEncoding.EncodeToString(seed),
	} {
		got, err := ParseSigningSeed(enc)
		if err != nil || len(got) != 32 {
			t.Errorf("ParseSigningSeed(%q): len=%d err=%v", enc, len(got), err)
		}
	}
	if _, err := ParseSigningSeed("!!not-base64!!"); err == nil {
		t.Error("invalid base64 accepted")
	}
}

func TestJWKSShape(t *testing.T) {
	iss := testIssuer(t, 0)
	jwks := iss.JWKS()
	if len(jwks.Keys) != 1 {
		t.Fatalf("keys = %d, want 1", len(jwks.Keys))
	}
	k := jwks.Keys[0]
	if k.Kty != "OKP" || k.Crv != "Ed25519" || k.Alg != "EdDSA" || k.Use != "sig" {
		t.Errorf("jwk = %+v", k)
	}
	pub, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil || len(pub) != 32 {
		t.Errorf("x decodes to %d bytes, err %v", len(pub), err)
	}
	if k.Kid == "" {
		t.Error("kid missing")
	}
}
