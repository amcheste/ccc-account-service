package auth

import (
	"bytes"
	"testing"
)

func TestNewRefreshToken(t *testing.T) {
	token, hash, err := NewRefreshToken()
	if err != nil {
		t.Fatal(err)
	}
	if len(token) < 40 {
		t.Errorf("token %q shorter than 256 bits encoded", token)
	}
	if !bytes.Equal(hash, HashRefreshToken(token)) {
		t.Error("returned hash does not match HashRefreshToken(token)")
	}

	token2, hash2, _ := NewRefreshToken()
	if token == token2 || bytes.Equal(hash, hash2) {
		t.Error("two generated tokens are identical")
	}
}
