// Package store implements PostgreSQL persistence (pgx) for users,
// credentials, and refresh tokens, plus embedded SQL migrations. The
// service layer depends on the Store interface so unit tests can
// substitute an in-memory fake.
package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	// ErrNotFound is returned when the requested row does not exist.
	ErrNotFound = errors.New("store: not found")
	// ErrDuplicateUsername is returned when a username is already
	// taken (case-insensitive; the column is citext).
	ErrDuplicateUsername = errors.New("store: username already exists")
)

// Role and status values match the CHECK constraints in the schema and
// the ccc.account.v1 proto enums.
const (
	RoleAdmin  = "admin"
	RoleMember = "member"

	StatusActive   = "active"
	StatusDisabled = "disabled"
)

// User is a household account row.
type User struct {
	ID          uuid.UUID
	Username    string
	DisplayName string
	Email       *string
	Role        string
	Status      string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Credential is the password record for a user.
type Credential struct {
	UserID       uuid.UUID
	Kind         string
	PasswordHash string
	MustChange   bool
	UpdatedAt    time.Time
}

// RefreshToken is one session: an opaque token identified by its
// SHA-256 hash, rotated on every refresh.
type RefreshToken struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	TokenHash  []byte
	DeviceName *string
	IssuedAt   time.Time
	ExpiresAt  time.Time
	RevokedAt  *time.Time
	ReplacedBy *uuid.UUID
}

// Active reports whether the token is usable at the given instant.
func (t RefreshToken) Active(now time.Time) bool {
	return t.RevokedAt == nil && t.ReplacedBy == nil && now.Before(t.ExpiresAt)
}

// CreateUserParams are the fields required to create a user.
type CreateUserParams struct {
	Username    string
	DisplayName string
	Role        string
}

// UpdateUserParams applies only its non-nil fields.
type UpdateUserParams struct {
	ID          uuid.UUID
	DisplayName *string
	Email       *string
	Role        *string
	Status      *string
}

// Store is the persistence surface the service layer builds on.
type Store interface {
	// Users
	CreateUser(ctx context.Context, p CreateUserParams) (User, error)
	GetUser(ctx context.Context, id uuid.UUID) (User, error)
	GetUserByUsername(ctx context.Context, username string) (User, error)
	ListUsers(ctx context.Context) ([]User, error)
	UpdateUser(ctx context.Context, p UpdateUserParams) (User, error)
	CountUsers(ctx context.Context) (int64, error)

	// Credentials
	GetCredential(ctx context.Context, userID uuid.UUID) (Credential, error)
	SetCredential(ctx context.Context, userID uuid.UUID, passwordHash string, mustChange bool) error

	// Refresh tokens
	CreateRefreshToken(ctx context.Context, t RefreshToken) error
	GetRefreshTokenByHash(ctx context.Context, tokenHash []byte) (RefreshToken, error)
	// ReplaceRefreshToken marks old as revoked and replaced by newID
	// (rotation). The new token must already exist.
	ReplaceRefreshToken(ctx context.Context, oldID, newID uuid.UUID) error
	RevokeRefreshToken(ctx context.Context, id uuid.UUID) error
	// RevokeRefreshTokenChain revokes the token and everything it was
	// rotated into (stolen-token tripwire; see design §4).
	RevokeRefreshTokenChain(ctx context.Context, id uuid.UUID) error
	// RevokeUserRefreshTokens revokes every unrevoked token for the
	// user, optionally sparing one (the current session).
	RevokeUserRefreshTokens(ctx context.Context, userID uuid.UUID, except *uuid.UUID) error
	// ListUserSessions returns unrevoked, unreplaced, unexpired tokens.
	ListUserSessions(ctx context.Context, userID uuid.UUID) ([]RefreshToken, error)

	// Ping verifies database connectivity (readiness probe).
	Ping(ctx context.Context) error
	Close()
}
