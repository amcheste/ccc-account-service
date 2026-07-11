//go:build integration

package store

import (
	"context"
	"crypto/rand"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

var pg *Postgres

func TestMain(m *testing.M) {
	ctx := context.Background()

	container, err := tcpostgres.Run(ctx, "postgres:17-alpine",
		tcpostgres.WithDatabase("account"),
		tcpostgres.WithUsername("ccc"),
		tcpostgres.WithPassword("integration-only"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).WithStartupTimeout(60*time.Second)),
	)
	if err != nil {
		panic("start postgres container: " + err.Error())
	}

	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		panic(err)
	}

	// Run twice to prove idempotence.
	if err := Migrate(dsn); err != nil {
		panic("first migrate: " + err.Error())
	}
	if err := Migrate(dsn); err != nil {
		panic("second migrate (idempotence): " + err.Error())
	}

	pg, err = Connect(ctx, dsn)
	if err != nil {
		panic(err)
	}

	code := m.Run()
	pg.Close()
	_ = container.Terminate(ctx)
	os.Exit(code)
}

func mustCreateUser(t *testing.T, username string) User {
	t.Helper()
	u, err := pg.CreateUser(context.Background(), CreateUserParams{
		Username: username, DisplayName: "Test " + username, Role: RoleMember,
	})
	if err != nil {
		t.Fatalf("CreateUser(%s): %v", username, err)
	}
	return u
}

func randomHash(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestUserLifecycle(t *testing.T) {
	ctx := context.Background()
	u := mustCreateUser(t, "lifecycle")

	if u.Status != StatusActive {
		t.Errorf("new user status = %q, want active", u.Status)
	}

	// Case-insensitive lookup: citext.
	got, err := pg.GetUserByUsername(ctx, "LIFECYCLE")
	if err != nil || got.ID != u.ID {
		t.Errorf("case-insensitive lookup: got %v err %v", got.ID, err)
	}

	// Duplicate username, different case.
	if _, err := pg.CreateUser(ctx, CreateUserParams{
		Username: "LifeCycle", DisplayName: "dup", Role: RoleMember,
	}); err != ErrDuplicateUsername {
		t.Errorf("duplicate create err = %v, want ErrDuplicateUsername", err)
	}

	// Partial update: only status.
	disabled := StatusDisabled
	updated, err := pg.UpdateUser(ctx, UpdateUserParams{ID: u.ID, Status: &disabled})
	if err != nil || updated.Status != StatusDisabled {
		t.Errorf("update status: %v err %v", updated.Status, err)
	}
	if updated.DisplayName != u.DisplayName {
		t.Errorf("partial update touched display_name: %q", updated.DisplayName)
	}

	if _, err := pg.GetUser(ctx, uuid.Must(uuid.NewV7())); err != ErrNotFound {
		t.Errorf("missing user err = %v, want ErrNotFound", err)
	}
}

func TestCredentials(t *testing.T) {
	ctx := context.Background()
	u := mustCreateUser(t, "creds")

	if _, err := pg.GetCredential(ctx, u.ID); err != ErrNotFound {
		t.Fatalf("empty credential err = %v, want ErrNotFound", err)
	}
	if err := pg.SetCredential(ctx, u.ID, "hash-one", true); err != nil {
		t.Fatal(err)
	}
	c, err := pg.GetCredential(ctx, u.ID)
	if err != nil || c.PasswordHash != "hash-one" || !c.MustChange {
		t.Fatalf("credential = %+v err %v", c, err)
	}
	// Upsert replaces.
	if err := pg.SetCredential(ctx, u.ID, "hash-two", false); err != nil {
		t.Fatal(err)
	}
	c, _ = pg.GetCredential(ctx, u.ID)
	if c.PasswordHash != "hash-two" || c.MustChange {
		t.Fatalf("after upsert credential = %+v", c)
	}
}

func newToken(t *testing.T, userID uuid.UUID) RefreshToken {
	t.Helper()
	return RefreshToken{
		ID:        uuid.Must(uuid.NewV7()),
		UserID:    userID,
		TokenHash: randomHash(t),
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
	}
}

func TestRefreshTokenRotationAndChainRevocation(t *testing.T) {
	ctx := context.Background()
	u := mustCreateUser(t, "rotation")

	// Simulate two rotations: t1 -> t2 -> t3.
	t1, t2, t3 := newToken(t, u.ID), newToken(t, u.ID), newToken(t, u.ID)
	for _, tok := range []RefreshToken{t1, t2, t3} {
		if err := pg.CreateRefreshToken(ctx, tok); err != nil {
			t.Fatal(err)
		}
	}
	if err := pg.ReplaceRefreshToken(ctx, t1.ID, t2.ID); err != nil {
		t.Fatal(err)
	}
	if err := pg.ReplaceRefreshToken(ctx, t2.ID, t3.ID); err != nil {
		t.Fatal(err)
	}

	// Double-replace must fail: the WHERE replaced_by IS NULL guard.
	if err := pg.ReplaceRefreshToken(ctx, t1.ID, t3.ID); err != ErrNotFound {
		t.Errorf("double replace err = %v, want ErrNotFound", err)
	}

	// Only the tail is an active session.
	sessions, err := pg.ListUserSessions(ctx, u.ID)
	if err != nil || len(sessions) != 1 || sessions[0].ID != t3.ID {
		t.Fatalf("sessions = %v err %v, want only t3", sessions, err)
	}

	// Reuse detection fires on t1: revoking its chain kills t3 too.
	if err := pg.RevokeRefreshTokenChain(ctx, t1.ID); err != nil {
		t.Fatal(err)
	}
	got, err := pg.GetRefreshTokenByHash(ctx, t3.TokenHash)
	if err != nil {
		t.Fatal(err)
	}
	if got.RevokedAt == nil {
		t.Error("chain revocation did not reach the active tail token")
	}
}

func TestRevokeUserRefreshTokensWithException(t *testing.T) {
	ctx := context.Background()
	u := mustCreateUser(t, "bulkrevoke")

	keep, drop := newToken(t, u.ID), newToken(t, u.ID)
	for _, tok := range []RefreshToken{keep, drop} {
		if err := pg.CreateRefreshToken(ctx, tok); err != nil {
			t.Fatal(err)
		}
	}
	if err := pg.RevokeUserRefreshTokens(ctx, u.ID, &keep.ID); err != nil {
		t.Fatal(err)
	}
	sessions, err := pg.ListUserSessions(ctx, u.ID)
	if err != nil || len(sessions) != 1 || sessions[0].ID != keep.ID {
		t.Fatalf("sessions = %v err %v, want only the spared token", sessions, err)
	}
}
