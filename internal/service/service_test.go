package service

import (
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/amcheste/ccc-account-service/internal/auth"
	"github.com/amcheste/ccc-account-service/internal/store"
	"github.com/amcheste/ccc-account-service/internal/store/storetest"
)

func testService(t *testing.T) (*Service, *storetest.Fake) {
	t.Helper()
	fake := storetest.New()
	hasher := auth.NewHasher(auth.Argon2Params{
		MemoryKiB: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLen: 16, KeyLen: 32,
	}, 2)
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	issuer, err := auth.NewTokenIssuer(seed, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return New(fake, hasher, issuer, time.Hour, slog.Default()), fake
}

func TestBootstrapCreatesFirstAdminOnce(t *testing.T) {
	s, fake := testService(t)
	ctx := context.Background()

	if err := s.Bootstrap(ctx, "alan", "initial-password"); err != nil {
		t.Fatal(err)
	}
	n, _ := fake.CountUsers(ctx)
	if n != 1 {
		t.Fatalf("users after bootstrap = %d, want 1", n)
	}
	u, err := fake.GetUserByUsername(ctx, "alan")
	if err != nil || u.Role != store.RoleAdmin {
		t.Fatalf("bootstrap admin: %+v err %v", u, err)
	}

	// Second bootstrap is a no-op even with a different name.
	if err := s.Bootstrap(ctx, "eve", "x"); err != nil {
		t.Fatal(err)
	}
	if n, _ := fake.CountUsers(ctx); n != 1 {
		t.Errorf("users after second bootstrap = %d, want 1", n)
	}

	// Bootstrap login carries must_change.
	sess, err := s.Login(ctx, "alan", "initial-password", "test")
	if err != nil || !sess.MustChange {
		t.Errorf("bootstrap login: mustChange=%v err=%v", sess.MustChange, err)
	}
}

func TestLoginFlows(t *testing.T) {
	s, _ := testService(t)
	ctx := context.Background()
	if err := s.Bootstrap(ctx, "alan", "correct-password"); err != nil {
		t.Fatal(err)
	}

	if _, err := s.Login(ctx, "alan", "wrong", "d"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("wrong password err = %v", err)
	}
	if _, err := s.Login(ctx, "nobody", "x", "d"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("unknown user err = %v", err)
	}

	sess, err := s.Login(ctx, "ALAN", "correct-password", "laptop")
	if err != nil {
		t.Fatalf("case-insensitive login: %v", err)
	}
	if sess.AccessToken == "" || sess.RefreshToken == "" {
		t.Error("session missing tokens")
	}

	// Disabled accounts cannot log in.
	disabled := store.StatusDisabled
	if _, err := s.UpdateUser(ctx, UpdateUserParams{ID: sess.User.ID, Status: &disabled}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Login(ctx, "alan", "correct-password", "d"); !errors.Is(err, ErrAccountDisabled) {
		t.Errorf("disabled login err = %v", err)
	}
}

func TestRefreshRotationAndReuseDetection(t *testing.T) {
	s, fake := testService(t)
	ctx := context.Background()
	if err := s.Bootstrap(ctx, "alan", "pw"); err != nil {
		t.Fatal(err)
	}
	first, err := s.Login(ctx, "alan", "pw", "laptop")
	if err != nil {
		t.Fatal(err)
	}

	second, err := s.Refresh(ctx, first.RefreshToken)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if second.RefreshToken == first.RefreshToken {
		t.Error("refresh did not rotate the token")
	}

	// Reusing the rotated token trips the tripwire...
	if _, err := s.Refresh(ctx, first.RefreshToken); !errors.Is(err, ErrInvalidSession) {
		t.Errorf("reuse err = %v", err)
	}
	// ...and the whole chain, including the fresh token, is dead.
	if _, err := s.Refresh(ctx, second.RefreshToken); !errors.Is(err, ErrInvalidSession) {
		t.Errorf("chain tail after reuse err = %v", err)
	}
	sessions, _ := s.ListSessions(ctx, first.User.ID, nil)
	if len(sessions) != 0 {
		t.Errorf("active sessions after chain revocation = %d, want 0", len(sessions))
	}
	_ = fake
}

func TestLogoutIsIdempotent(t *testing.T) {
	s, _ := testService(t)
	ctx := context.Background()
	if err := s.Bootstrap(ctx, "alan", "pw"); err != nil {
		t.Fatal(err)
	}
	sess, _ := s.Login(ctx, "alan", "pw", "d")

	if err := s.Logout(ctx, sess.RefreshToken); err != nil {
		t.Fatal(err)
	}
	if err := s.Logout(ctx, sess.RefreshToken); err != nil {
		t.Errorf("second logout: %v", err)
	}
	if _, err := s.Refresh(ctx, sess.RefreshToken); !errors.Is(err, ErrInvalidSession) {
		t.Errorf("refresh after logout err = %v", err)
	}
}

func TestChangePasswordRevokesOtherSessions(t *testing.T) {
	s, _ := testService(t)
	ctx := context.Background()
	if err := s.Bootstrap(ctx, "alan", "old-password"); err != nil {
		t.Fatal(err)
	}
	laptop, _ := s.Login(ctx, "alan", "old-password", "laptop")
	tablet, _ := s.Login(ctx, "alan", "old-password", "tablet")

	if err := s.ChangePassword(ctx, laptop.User.ID, "wrong", "new-password-12", &laptop.TokenID); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("wrong current password err = %v", err)
	}
	if err := s.ChangePassword(ctx, laptop.User.ID, "old-password", "new-password-12", &laptop.TokenID); err != nil {
		t.Fatal(err)
	}

	// Old password dead, new one works, must_change cleared.
	if _, err := s.Login(ctx, "alan", "old-password", "d"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("old password still works: %v", err)
	}
	sess, err := s.Login(ctx, "alan", "new-password-12", "d")
	if err != nil || sess.MustChange {
		t.Errorf("new password login: mustChange=%v err=%v", sess.MustChange, err)
	}

	// The tablet session is revoked, the laptop session survives.
	if _, err := s.Refresh(ctx, tablet.RefreshToken); !errors.Is(err, ErrInvalidSession) {
		t.Errorf("tablet session survived password change: %v", err)
	}
	if _, err := s.Refresh(ctx, laptop.RefreshToken); err != nil {
		t.Errorf("laptop session should survive: %v", err)
	}
}

func TestAdminResetForcesChange(t *testing.T) {
	s, _ := testService(t)
	ctx := context.Background()
	if err := s.Bootstrap(ctx, "alan", "pw"); err != nil {
		t.Fatal(err)
	}
	member, temp, err := s.CreateUser(ctx, "sam", "Sam", store.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := s.Login(ctx, "sam", temp, "d")
	if err != nil || !sess.MustChange {
		t.Fatalf("temp password login: mustChange=%v err=%v", sess.MustChange, err)
	}

	temp2, err := s.ResetPassword(ctx, member.ID)
	if err != nil {
		t.Fatal(err)
	}
	if temp2 == temp {
		t.Error("reset produced the same temp password")
	}
	// Reset revoked the session opened with the old temp password.
	if _, err := s.Refresh(ctx, sess.RefreshToken); !errors.Is(err, ErrInvalidSession) {
		t.Errorf("session survived password reset: %v", err)
	}
}

func TestDisableRevokesSessionsAndSessionOwnership(t *testing.T) {
	s, _ := testService(t)
	ctx := context.Background()
	if err := s.Bootstrap(ctx, "alan", "pw"); err != nil {
		t.Fatal(err)
	}
	_, temp, _ := s.CreateUser(ctx, "sam", "Sam", store.RoleMember)
	samSess, _ := s.Login(ctx, "sam", temp, "d")
	alanSess, _ := s.Login(ctx, "alan", "pw", "d")

	// Sam cannot revoke Alan's session.
	if err := s.RevokeSession(ctx, samSess.User.ID, alanSess.TokenID); !errors.Is(err, ErrNotFound) {
		t.Errorf("cross-user revoke err = %v", err)
	}

	disabled := store.StatusDisabled
	if _, err := s.UpdateUser(ctx, UpdateUserParams{ID: samSess.User.ID, Status: &disabled}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Refresh(ctx, samSess.RefreshToken); !errors.Is(err, ErrInvalidSession) && !errors.Is(err, ErrAccountDisabled) {
		t.Errorf("disabled user session survived: %v", err)
	}
}
