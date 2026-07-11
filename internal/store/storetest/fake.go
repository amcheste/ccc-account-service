// Package storetest provides an in-memory store.Store for unit tests
// of the service and transport layers. Semantics mirror the Postgres
// implementation, including rotation-chain behavior.
package storetest

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/amcheste/ccc-account-service/internal/store"
)

// Fake is a threadsafe in-memory store.Store.
type Fake struct {
	mu          sync.Mutex
	users       map[uuid.UUID]store.User
	credentials map[uuid.UUID]store.Credential
	tokens      map[uuid.UUID]store.RefreshToken
}

var _ store.Store = (*Fake)(nil)

// New returns an empty fake store.
func New() *Fake {
	return &Fake{
		users:       map[uuid.UUID]store.User{},
		credentials: map[uuid.UUID]store.Credential{},
		tokens:      map[uuid.UUID]store.RefreshToken{},
	}
}

// CreateUser mirrors Postgres semantics including case-insensitive
// username uniqueness.
func (f *Fake) CreateUser(_ context.Context, p store.CreateUserParams) (store.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, u := range f.users {
		if strings.EqualFold(u.Username, p.Username) {
			return store.User{}, store.ErrDuplicateUsername
		}
	}
	now := time.Now()
	u := store.User{
		ID:          uuid.Must(uuid.NewV7()),
		Username:    p.Username,
		DisplayName: p.DisplayName,
		Role:        p.Role,
		Status:      store.StatusActive,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	f.users[u.ID] = u
	return u, nil
}

// GetUser fetches by id.
func (f *Fake) GetUser(_ context.Context, id uuid.UUID) (store.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.users[id]
	if !ok {
		return store.User{}, store.ErrNotFound
	}
	return u, nil
}

// GetUserByUsername fetches case-insensitively.
func (f *Fake) GetUserByUsername(_ context.Context, username string) (store.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, u := range f.users {
		if strings.EqualFold(u.Username, username) {
			return u, nil
		}
	}
	return store.User{}, store.ErrNotFound
}

// ListUsers returns users ordered by creation time.
func (f *Fake) ListUsers(_ context.Context) ([]store.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []store.User
	for _, u := range f.users {
		out = append(out, u)
	}
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j].CreatedAt.Before(out[i].CreatedAt) {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out, nil
}

// UpdateUser applies non-nil fields.
func (f *Fake) UpdateUser(_ context.Context, p store.UpdateUserParams) (store.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.users[p.ID]
	if !ok {
		return store.User{}, store.ErrNotFound
	}
	if p.DisplayName != nil {
		u.DisplayName = *p.DisplayName
	}
	if p.Email != nil {
		u.Email = p.Email
	}
	if p.Role != nil {
		u.Role = *p.Role
	}
	if p.Status != nil {
		u.Status = *p.Status
	}
	u.UpdatedAt = time.Now()
	f.users[p.ID] = u
	return u, nil
}

// CountUsers returns the user count.
func (f *Fake) CountUsers(_ context.Context) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return int64(len(f.users)), nil
}

// GetCredential fetches a credential.
func (f *Fake) GetCredential(_ context.Context, userID uuid.UUID) (store.Credential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.credentials[userID]
	if !ok {
		return store.Credential{}, store.ErrNotFound
	}
	return c, nil
}

// SetCredential upserts a credential.
func (f *Fake) SetCredential(_ context.Context, userID uuid.UUID, hash string, mustChange bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.credentials[userID] = store.Credential{
		UserID: userID, Kind: "password", PasswordHash: hash,
		MustChange: mustChange, UpdatedAt: time.Now(),
	}
	return nil
}

// CreateRefreshToken inserts a token.
func (f *Fake) CreateRefreshToken(_ context.Context, t store.RefreshToken) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tokens[t.ID] = t
	return nil
}

// GetRefreshTokenByHash looks a token up by hash.
func (f *Fake) GetRefreshTokenByHash(_ context.Context, hash []byte) (store.RefreshToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, t := range f.tokens {
		if bytes.Equal(t.TokenHash, hash) {
			return t, nil
		}
	}
	return store.RefreshToken{}, store.ErrNotFound
}

// ReplaceRefreshToken mirrors the replaced_by IS NULL guard.
func (f *Fake) ReplaceRefreshToken(_ context.Context, oldID, newID uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.tokens[oldID]
	if !ok || t.ReplacedBy != nil {
		return store.ErrNotFound
	}
	now := time.Now()
	t.RevokedAt = &now
	t.ReplacedBy = &newID
	f.tokens[oldID] = t
	return nil
}

// RevokeRefreshToken revokes one unrevoked token.
func (f *Fake) RevokeRefreshToken(_ context.Context, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.tokens[id]
	if !ok || t.RevokedAt != nil {
		return store.ErrNotFound
	}
	now := time.Now()
	t.RevokedAt = &now
	f.tokens[id] = t
	return nil
}

// RevokeRefreshTokenChain revokes the token and all rotation
// descendants.
func (f *Fake) RevokeRefreshTokenChain(_ context.Context, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	for cur, ok := f.tokens[id]; ok; cur, ok = f.tokens[*cur.ReplacedBy] {
		if cur.RevokedAt == nil {
			cur.RevokedAt = &now
			f.tokens[cur.ID] = cur
		}
		if cur.ReplacedBy == nil {
			break
		}
	}
	return nil
}

// RevokeUserRefreshTokens revokes all of a user's tokens, sparing one.
func (f *Fake) RevokeUserRefreshTokens(_ context.Context, userID uuid.UUID, except *uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	for id, t := range f.tokens {
		if t.UserID != userID || t.RevokedAt != nil {
			continue
		}
		if except != nil && id == *except {
			continue
		}
		t.RevokedAt = &now
		f.tokens[id] = t
	}
	return nil
}

// ListUserSessions returns active tokens, newest first.
func (f *Fake) ListUserSessions(_ context.Context, userID uuid.UUID) ([]store.RefreshToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	var out []store.RefreshToken
	for _, t := range f.tokens {
		if t.UserID == userID && t.Active(now) {
			out = append(out, t)
		}
	}
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j].IssuedAt.After(out[i].IssuedAt) {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out, nil
}

// Ping always succeeds.
func (f *Fake) Ping(context.Context) error { return nil }

// Close is a no-op.
func (f *Fake) Close() {}
