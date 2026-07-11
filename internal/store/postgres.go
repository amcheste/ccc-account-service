package store

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const uniqueViolation = "23505"

// Postgres implements Store on a pgx connection pool.
type Postgres struct {
	pool *pgxpool.Pool
}

var _ Store = (*Postgres)(nil)

// Connect opens a pool and verifies connectivity.
func Connect(ctx context.Context, dsn string) (*Postgres, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("open pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return &Postgres{pool: pool}, nil
}

// Ping verifies database connectivity.
func (p *Postgres) Ping(ctx context.Context) error { return p.pool.Ping(ctx) }

// Close releases the connection pool.
func (p *Postgres) Close() { p.pool.Close() }

const userColumns = "id, username, display_name, email, role, status, created_at, updated_at"

func scanUser(row pgx.Row) (User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Username, &u.DisplayName, &u.Email, &u.Role,
		&u.Status, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

// CreateUser inserts an active user with a v7 UUID.
func (p *Postgres) CreateUser(ctx context.Context, params CreateUserParams) (User, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return User{}, err
	}
	row := p.pool.QueryRow(ctx,
		`INSERT INTO users (id, username, display_name, role, status)
		 VALUES ($1, $2, $3, $4, $5) RETURNING `+userColumns,
		id, params.Username, params.DisplayName, params.Role, StatusActive)
	u, err := scanUser(row)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
		return User{}, ErrDuplicateUsername
	}
	return u, err
}

// GetUser fetches a user by id.
func (p *Postgres) GetUser(ctx context.Context, id uuid.UUID) (User, error) {
	return scanUser(p.pool.QueryRow(ctx,
		`SELECT `+userColumns+` FROM users WHERE id = $1`, id))
}

// GetUserByUsername fetches a user by name, case-insensitively (citext).
func (p *Postgres) GetUserByUsername(ctx context.Context, username string) (User, error) {
	return scanUser(p.pool.QueryRow(ctx,
		`SELECT `+userColumns+` FROM users WHERE username = $1`, username))
}

// ListUsers returns all users ordered by creation time.
func (p *Postgres) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT `+userColumns+` FROM users ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// UpdateUser applies the non-nil fields of params.
func (p *Postgres) UpdateUser(ctx context.Context, params UpdateUserParams) (User, error) {
	sets := []string{"updated_at = now()"}
	args := []any{params.ID}
	add := func(col string, val any) {
		args = append(args, val)
		sets = append(sets, fmt.Sprintf("%s = $%d", col, len(args)))
	}
	if params.DisplayName != nil {
		add("display_name", *params.DisplayName)
	}
	if params.Email != nil {
		add("email", *params.Email)
	}
	if params.Role != nil {
		add("role", *params.Role)
	}
	if params.Status != nil {
		add("status", *params.Status)
	}
	return scanUser(p.pool.QueryRow(ctx,
		`UPDATE users SET `+strings.Join(sets, ", ")+
			` WHERE id = $1 RETURNING `+userColumns, args...))
}

// CountUsers returns the total user count (first-admin bootstrap).
func (p *Postgres) CountUsers(ctx context.Context) (int64, error) {
	var n int64
	err := p.pool.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&n)
	return n, err
}

// GetCredential fetches the password credential for a user.
func (p *Postgres) GetCredential(ctx context.Context, userID uuid.UUID) (Credential, error) {
	var c Credential
	err := p.pool.QueryRow(ctx,
		`SELECT user_id, kind, password_hash, must_change, updated_at
		 FROM credentials WHERE user_id = $1`, userID).
		Scan(&c.UserID, &c.Kind, &c.PasswordHash, &c.MustChange, &c.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Credential{}, ErrNotFound
	}
	return c, err
}

// SetCredential upserts the password hash and must-change flag.
func (p *Postgres) SetCredential(ctx context.Context, userID uuid.UUID, passwordHash string, mustChange bool) error {
	_, err := p.pool.Exec(ctx,
		`INSERT INTO credentials (user_id, password_hash, must_change)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (user_id) DO UPDATE
		 SET password_hash = $2, must_change = $3, updated_at = now()`,
		userID, passwordHash, mustChange)
	return err
}

const tokenColumns = "id, user_id, token_hash, device_name, issued_at, expires_at, revoked_at, replaced_by" //nolint:gosec // column list, not a credential

func scanToken(row pgx.Row) (RefreshToken, error) {
	var t RefreshToken
	err := row.Scan(&t.ID, &t.UserID, &t.TokenHash, &t.DeviceName,
		&t.IssuedAt, &t.ExpiresAt, &t.RevokedAt, &t.ReplacedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return RefreshToken{}, ErrNotFound
	}
	return t, err
}

// CreateRefreshToken inserts a new refresh token row.
func (p *Postgres) CreateRefreshToken(ctx context.Context, t RefreshToken) error {
	_, err := p.pool.Exec(ctx,
		`INSERT INTO refresh_tokens (id, user_id, token_hash, device_name, issued_at, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		t.ID, t.UserID, t.TokenHash, t.DeviceName, t.IssuedAt, t.ExpiresAt)
	return err
}

// GetRefreshTokenByHash looks a token up by its SHA-256 hash.
func (p *Postgres) GetRefreshTokenByHash(ctx context.Context, tokenHash []byte) (RefreshToken, error) {
	return scanToken(p.pool.QueryRow(ctx,
		`SELECT `+tokenColumns+` FROM refresh_tokens WHERE token_hash = $1`,
		tokenHash))
}

// ReplaceRefreshToken revokes old and records newID as its rotation
// successor; fails with ErrNotFound if old was already replaced.
func (p *Postgres) ReplaceRefreshToken(ctx context.Context, oldID, newID uuid.UUID) error {
	tag, err := p.pool.Exec(ctx,
		`UPDATE refresh_tokens SET revoked_at = now(), replaced_by = $2
		 WHERE id = $1 AND replaced_by IS NULL`, oldID, newID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// RevokeRefreshToken revokes a single unrevoked token.
func (p *Postgres) RevokeRefreshToken(ctx context.Context, id uuid.UUID) error {
	tag, err := p.pool.Exec(ctx,
		`UPDATE refresh_tokens SET revoked_at = now()
		 WHERE id = $1 AND revoked_at IS NULL`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// RevokeRefreshTokenChain revokes the token and every rotation
// descendant (reuse-detection tripwire, design §4).
func (p *Postgres) RevokeRefreshTokenChain(ctx context.Context, id uuid.UUID) error {
	// Walk the rotation chain forward from the presented token and
	// revoke every descendant, including the currently active tail.
	_, err := p.pool.Exec(ctx,
		`WITH RECURSIVE chain AS (
		     SELECT id, replaced_by FROM refresh_tokens WHERE id = $1
		     UNION ALL
		     SELECT rt.id, rt.replaced_by
		     FROM refresh_tokens rt
		     JOIN chain c ON rt.id = c.replaced_by
		 )
		 UPDATE refresh_tokens SET revoked_at = now()
		 WHERE id IN (SELECT id FROM chain) AND revoked_at IS NULL`, id)
	return err
}

// RevokeUserRefreshTokens revokes all of a user's unrevoked tokens,
// optionally sparing one.
func (p *Postgres) RevokeUserRefreshTokens(ctx context.Context, userID uuid.UUID, except *uuid.UUID) error {
	_, err := p.pool.Exec(ctx,
		`UPDATE refresh_tokens SET revoked_at = now()
		 WHERE user_id = $1 AND revoked_at IS NULL AND ($2::uuid IS NULL OR id <> $2)`,
		userID, except)
	return err
}

// ListUserSessions returns active (unrevoked, unreplaced, unexpired)
// tokens, newest first.
func (p *Postgres) ListUserSessions(ctx context.Context, userID uuid.UUID) ([]RefreshToken, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT `+tokenColumns+` FROM refresh_tokens
		 WHERE user_id = $1 AND revoked_at IS NULL AND replaced_by IS NULL
		   AND expires_at > now()
		 ORDER BY issued_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []RefreshToken
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, t)
	}
	return tokens, rows.Err()
}
