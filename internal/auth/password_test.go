package auth

import (
	"errors"
	"strings"
	"testing"
)

// Small parameters keep tests fast; production uses DefaultParams.
func testHasher() *Hasher {
	return NewHasher(Argon2Params{
		MemoryKiB: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLen: 16, KeyLen: 32,
	}, 2)
}

func TestHashVerifyRoundTrip(t *testing.T) {
	h := testHasher()
	phc, err := h.Hash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(phc, "$argon2id$v=19$m=8192,t=1,p=1$") {
		t.Errorf("PHC prefix wrong: %s", phc)
	}
	needsRehash, err := h.Verify("correct horse battery staple", phc)
	if err != nil || needsRehash {
		t.Errorf("verify: needsRehash=%v err=%v", needsRehash, err)
	}
}

func TestVerifyWrongPassword(t *testing.T) {
	h := testHasher()
	phc, _ := h.Hash("right")
	if _, err := h.Verify("wrong", phc); !errors.Is(err, ErrWrongPassword) {
		t.Errorf("err = %v, want ErrWrongPassword", err)
	}
}

func TestUniqueSalts(t *testing.T) {
	h := testHasher()
	a, _ := h.Hash("same password")
	b, _ := h.Hash("same password")
	if a == b {
		t.Error("two hashes of the same password are identical; salt reuse")
	}
}

func TestNeedsRehashOnWeakerParams(t *testing.T) {
	weak := NewHasher(Argon2Params{
		MemoryKiB: 4 * 1024, Iterations: 1, Parallelism: 1, SaltLen: 16, KeyLen: 32,
	}, 1)
	phc, _ := weak.Hash("pw")

	strong := testHasher() // 8 MiB > 4 MiB
	needsRehash, err := strong.Verify("pw", phc)
	if err != nil {
		t.Fatal(err)
	}
	if !needsRehash {
		t.Error("hash with weaker params should request rehash")
	}
}

func TestVerifyMalformedHash(t *testing.T) {
	h := testHasher()
	for _, phc := range []string{
		"", "plainhash", "$argon2i$v=19$m=8,t=1,p=1$c2FsdA$aGFzaA",
		"$argon2id$v=18$m=8,t=1,p=1$c2FsdA$aGFzaA",
		"$argon2id$v=19$m=8,t=1,p=1$!!!$aGFzaA",
	} {
		if _, err := h.Verify("pw", phc); err == nil {
			t.Errorf("Verify(%q) accepted malformed hash", phc)
		}
	}
}
