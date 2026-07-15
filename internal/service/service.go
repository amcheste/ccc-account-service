// Package service holds the transport-agnostic business logic of the
// account service: login, token rotation with reuse detection, user
// lifecycle, and session management. Both the REST and gRPC layers
// call into this package; neither transport reaches the store
// directly.
package service

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/amcheste/ccc-account-service/internal/auth"
	"github.com/amcheste/ccc-account-service/internal/store"
)

// Sentinel errors the transports map to status codes.
var (
	ErrInvalidCredentials = errors.New("service: invalid credentials")
	ErrAccountDisabled    = errors.New("service: account disabled")
	ErrInvalidSession     = errors.New("service: invalid session")
	ErrNotFound           = store.ErrNotFound
	ErrDuplicateUsername  = store.ErrDuplicateUsername
)

// dummyPHC keeps login timing uniform when the username is unknown.
const dummyPHC = "$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$Wn8+Vf2pTLXqRJmZ0uMy4kL7d0h5cW1oQ2s3b1p4c2E"

// Service implements the account service use cases.
type Service struct {
	store      store.Store
	hasher     *auth.Hasher
	tokens     *auth.TokenIssuer
	refreshTTL time.Duration
	logger     *slog.Logger
	now        func() time.Time
}

// New wires the service. refreshTTL <= 0 defaults to 30 days.
func New(st store.Store, hasher *auth.Hasher, tokens *auth.TokenIssuer, refreshTTL time.Duration, logger *slog.Logger) *Service {
	if refreshTTL <= 0 {
		refreshTTL = 30 * 24 * time.Hour
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{
		store: st, hasher: hasher, tokens: tokens,
		refreshTTL: refreshTTL, logger: logger, now: time.Now,
	}
}

// Session is the result of a successful login or refresh.
type Session struct {
	AccessToken  string
	RefreshToken string // opaque; transported only in the HttpOnly cookie
	TokenID      uuid.UUID
	User         store.User
	MustChange   bool
}

// SessionInfo describes one active session for the sessions UI.
type SessionInfo struct {
	ID         uuid.UUID
	DeviceName *string
	IssuedAt   time.Time
	ExpiresAt  time.Time
	Current    bool
}

// Bootstrap creates the first admin when the store is empty (design
// §8: registration is closed; the first account comes from config).
func (s *Service) Bootstrap(ctx context.Context, username, password string) error {
	if username == "" {
		return nil
	}
	n, err := s.store.CountUsers(ctx)
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	if password == "" {
		return errors.New("service: bootstrap admin requires a password")
	}
	u, err := s.store.CreateUser(ctx, store.CreateUserParams{
		Username: username, DisplayName: username, Role: store.RoleAdmin,
	})
	if err != nil {
		return err
	}
	phc, err := s.hasher.Hash(password)
	if err != nil {
		return err
	}
	if err := s.store.SetCredential(ctx, u.ID, phc, true); err != nil {
		return err
	}
	s.logger.Info("bootstrap admin created", "event", "bootstrap_admin", "username", username)
	return nil
}

// Login verifies credentials and opens a new session.
func (s *Service) Login(ctx context.Context, username, password, deviceName string) (Session, error) {
	user, err := s.store.GetUserByUsername(ctx, username)
	if errors.Is(err, store.ErrNotFound) {
		// Equalize timing with the found-user path.
		_, _ = s.hasher.Verify(password, dummyPHC)
		s.logger.Info("login failed", "event", "login_failure", "username", username, "reason", "unknown user")
		return Session{}, ErrInvalidCredentials
	}
	if err != nil {
		return Session{}, err
	}

	cred, err := s.store.GetCredential(ctx, user.ID)
	if errors.Is(err, store.ErrNotFound) {
		_, _ = s.hasher.Verify(password, dummyPHC)
		return Session{}, ErrInvalidCredentials
	}
	if err != nil {
		return Session{}, err
	}

	needsRehash, err := s.hasher.Verify(password, cred.PasswordHash)
	if errors.Is(err, auth.ErrWrongPassword) {
		s.logger.Info("login failed", "event", "login_failure", "username", username, "reason", "wrong password")
		return Session{}, ErrInvalidCredentials
	}
	if err != nil {
		return Session{}, err
	}
	if user.Status != store.StatusActive {
		s.logger.Info("login refused", "event", "login_failure", "username", username, "reason", "disabled")
		return Session{}, ErrAccountDisabled
	}

	if needsRehash {
		if phc, err := s.hasher.Hash(password); err == nil {
			_ = s.store.SetCredential(ctx, user.ID, phc, cred.MustChange)
		}
	}

	sess, err := s.openSession(ctx, user, deviceName)
	if err != nil {
		return Session{}, err
	}
	sess.MustChange = cred.MustChange
	s.logger.Info("login", "event", "login_success", "username", username)
	return sess, nil
}

func (s *Service) openSession(ctx context.Context, user store.User, deviceName string) (Session, error) {
	opaque, hash, err := auth.NewRefreshToken()
	if err != nil {
		return Session{}, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return Session{}, err
	}
	var device *string
	if deviceName != "" {
		device = &deviceName
	}
	now := s.now()
	if err := s.store.CreateRefreshToken(ctx, store.RefreshToken{
		ID: id, UserID: user.ID, TokenHash: hash, DeviceName: device,
		IssuedAt: now, ExpiresAt: now.Add(s.refreshTTL),
	}); err != nil {
		return Session{}, err
	}
	access, err := s.tokens.Mint(user.ID, user.Username, []string{user.Role}, now)
	if err != nil {
		return Session{}, err
	}
	return Session{
		AccessToken: access, RefreshToken: opaque, TokenID: id, User: user,
	}, nil
}

// Refresh rotates a refresh token. Presenting an already-rotated or
// revoked token trips reuse detection: the whole chain is revoked
// (design §4).
func (s *Service) Refresh(ctx context.Context, refreshToken string) (Session, error) {
	tok, err := s.store.GetRefreshTokenByHash(ctx, auth.HashRefreshToken(refreshToken))
	if errors.Is(err, store.ErrNotFound) {
		return Session{}, ErrInvalidSession
	}
	if err != nil {
		return Session{}, err
	}

	now := s.now()
	if !tok.Active(now) {
		if tok.ReplacedBy != nil {
			// Reuse of a rotated token: assume theft, kill the chain.
			_ = s.store.RevokeRefreshTokenChain(ctx, tok.ID)
			s.logger.Warn("refresh token reuse detected; chain revoked",
				"event", "token_reuse", "user_id", tok.UserID)
		}
		return Session{}, ErrInvalidSession
	}

	user, err := s.store.GetUser(ctx, tok.UserID)
	if err != nil {
		return Session{}, err
	}
	if user.Status != store.StatusActive {
		_ = s.store.RevokeRefreshToken(ctx, tok.ID)
		return Session{}, ErrAccountDisabled
	}

	device := ""
	if tok.DeviceName != nil {
		device = *tok.DeviceName
	}
	sess, err := s.openSession(ctx, user, device)
	if err != nil {
		return Session{}, err
	}
	if err := s.store.ReplaceRefreshToken(ctx, tok.ID, sess.TokenID); err != nil {
		// Lost the rotation race; invalidate the token we just made.
		_ = s.store.RevokeRefreshToken(ctx, sess.TokenID)
		return Session{}, ErrInvalidSession
	}

	cred, err := s.store.GetCredential(ctx, user.ID)
	if err == nil {
		sess.MustChange = cred.MustChange
	}
	return sess, nil
}

// Logout revokes the presented session. Unknown tokens are a no-op:
// logout must be idempotent.
func (s *Service) Logout(ctx context.Context, refreshToken string) error {
	tok, err := s.store.GetRefreshTokenByHash(ctx, auth.HashRefreshToken(refreshToken))
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := s.store.RevokeRefreshToken(ctx, tok.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return nil
}

// GetUser fetches a user by id.
func (s *Service) GetUser(ctx context.Context, id uuid.UUID) (store.User, error) {
	return s.store.GetUser(ctx, id)
}

// ListUsers returns all users.
func (s *Service) ListUsers(ctx context.Context) ([]store.User, error) {
	return s.store.ListUsers(ctx)
}

// UpdateProfile lets a user change their own display name.
func (s *Service) UpdateProfile(ctx context.Context, userID uuid.UUID, displayName string) (store.User, error) {
	return s.store.UpdateUser(ctx, store.UpdateUserParams{ID: userID, DisplayName: &displayName})
}

// UpdateUserParams is the admin-side update surface.
type UpdateUserParams struct {
	ID          uuid.UUID
	DisplayName *string
	Role        *string
	Status      *string
}

// UpdateUser applies an admin update. Disabling a user revokes all of
// their sessions.
func (s *Service) UpdateUser(ctx context.Context, p UpdateUserParams) (store.User, error) {
	u, err := s.store.UpdateUser(ctx, store.UpdateUserParams{
		ID: p.ID, DisplayName: p.DisplayName, Role: p.Role, Status: p.Status,
	})
	if err != nil {
		return store.User{}, err
	}
	if p.Status != nil && *p.Status == store.StatusDisabled {
		if err := s.store.RevokeUserRefreshTokens(ctx, p.ID, nil); err != nil {
			return store.User{}, err
		}
		s.logger.Info("user disabled; sessions revoked", "event", "user_disabled", "user_id", p.ID)
	}
	return u, nil
}

// ChangePassword verifies the current password, stores the new hash,
// and signs out every other session. keepTokenID spares the caller's
// session; nil revokes everything.
func (s *Service) ChangePassword(ctx context.Context, userID uuid.UUID, current, newPassword string, keepTokenID *uuid.UUID) error {
	cred, err := s.store.GetCredential(ctx, userID)
	if err != nil {
		return err
	}
	if _, err := s.hasher.Verify(current, cred.PasswordHash); err != nil {
		if errors.Is(err, auth.ErrWrongPassword) {
			return ErrInvalidCredentials
		}
		return err
	}
	phc, err := s.hasher.Hash(newPassword)
	if err != nil {
		return err
	}
	if err := s.store.SetCredential(ctx, userID, phc, false); err != nil {
		return err
	}
	if err := s.store.RevokeUserRefreshTokens(ctx, userID, keepTokenID); err != nil {
		return err
	}
	s.logger.Info("password changed", "event", "password_change", "user_id", userID)
	return nil
}

// CreateUser is the admin path for adding a household member. The
// returned temporary password is shown exactly once.
func (s *Service) CreateUser(ctx context.Context, username, displayName, role string) (store.User, string, error) {
	u, err := s.store.CreateUser(ctx, store.CreateUserParams{
		Username: username, DisplayName: displayName, Role: role,
	})
	if err != nil {
		return store.User{}, "", err
	}
	temp, err := s.setTempPassword(ctx, u.ID)
	if err != nil {
		return store.User{}, "", err
	}
	s.logger.Info("user created", "event", "user_created", "username", username, "role", role)
	return u, temp, nil
}

// ResetPassword sets a fresh temporary password (admin path, no email
// per design §8) and revokes the user's sessions.
func (s *Service) ResetPassword(ctx context.Context, userID uuid.UUID) (string, error) {
	if _, err := s.store.GetUser(ctx, userID); err != nil {
		return "", err
	}
	temp, err := s.setTempPassword(ctx, userID)
	if err != nil {
		return "", err
	}
	if err := s.store.RevokeUserRefreshTokens(ctx, userID, nil); err != nil {
		return "", err
	}
	s.logger.Info("password reset", "event", "password_reset", "user_id", userID)
	return temp, nil
}

func (s *Service) setTempPassword(ctx context.Context, userID uuid.UUID) (string, error) {
	temp, err := temporaryPassword()
	if err != nil {
		return "", err
	}
	phc, err := s.hasher.Hash(temp)
	if err != nil {
		return "", err
	}
	if err := s.store.SetCredential(ctx, userID, phc, true); err != nil {
		return "", err
	}
	return temp, nil
}

// CurrentSessionID resolves a presented refresh token to its session
// id, or nil when the token is unknown or inactive. Transports use it
// to mark the caller's session and to spare it on password change.
func (s *Service) CurrentSessionID(ctx context.Context, refreshToken string) *uuid.UUID {
	if refreshToken == "" {
		return nil
	}
	tok, err := s.store.GetRefreshTokenByHash(ctx, auth.HashRefreshToken(refreshToken))
	if err != nil || !tok.Active(s.now()) {
		return nil
	}
	return &tok.ID
}

// ListSessions returns the user's active sessions, marking the caller's.
func (s *Service) ListSessions(ctx context.Context, userID uuid.UUID, currentTokenID *uuid.UUID) ([]SessionInfo, error) {
	tokens, err := s.store.ListUserSessions(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]SessionInfo, 0, len(tokens))
	for _, t := range tokens {
		out = append(out, SessionInfo{
			ID: t.ID, DeviceName: t.DeviceName,
			IssuedAt: t.IssuedAt, ExpiresAt: t.ExpiresAt,
			Current: currentTokenID != nil && t.ID == *currentTokenID,
		})
	}
	return out, nil
}

// RevokeSession revokes one of the caller's own sessions.
func (s *Service) RevokeSession(ctx context.Context, userID, sessionID uuid.UUID) error {
	sessions, err := s.store.ListUserSessions(ctx, userID)
	if err != nil {
		return err
	}
	for _, t := range sessions {
		if t.ID == sessionID {
			return s.store.RevokeRefreshToken(ctx, sessionID)
		}
	}
	return ErrNotFound
}

// temporaryPassword returns a readable 16-character one-time password.
func temporaryPassword() (string, error) {
	const alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789"
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate temp password: %w", err)
	}
	for i, b := range raw {
		raw[i] = alphabet[int(b)%len(alphabet)]
	}
	return string(raw), nil
}
