package httpserver

import (
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/amcheste/ccc-account-service/internal/service"
	"github.com/amcheste/ccc-account-service/internal/store"
)

// userJSON matches the shape the web client's zod schemas validate.
type userJSON struct {
	ID          string  `json:"id"`
	Username    string  `json:"username"`
	DisplayName string  `json:"display_name"`
	Role        string  `json:"role"`
	Status      string  `json:"status"`
	CreatedAt   string  `json:"created_at"`
	Email       *string `json:"email,omitempty"`
}

func toUserJSON(u store.User) userJSON {
	return userJSON{
		ID:          u.ID.String(),
		Username:    u.Username,
		DisplayName: u.DisplayName,
		Role:        u.Role,
		Status:      u.Status,
		CreatedAt:   u.CreatedAt.UTC().Format(time.RFC3339),
		Email:       u.Email,
	}
}

func (s *Server) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, s.tokens.JWKS())
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if !s.loginLimiter.allow("ip:"+clientIP(r), "user:"+body.Username) {
		writeProblem(w, http.StatusTooManyRequests, "Too many login attempts", "Try again in a minute.")
		return
	}

	sess, err := s.svc.Login(r.Context(), body.Username, body.Password, r.UserAgent())
	switch {
	case errors.Is(err, service.ErrInvalidCredentials):
		writeProblem(w, http.StatusUnauthorized, "Invalid credentials", "")
		return
	case errors.Is(err, service.ErrAccountDisabled):
		writeProblem(w, http.StatusForbidden, "Account disabled", "")
		return
	case err != nil:
		writeProblem(w, http.StatusInternalServerError, "Login failed", "")
		return
	}

	s.setRefreshCookie(w, sess.RefreshToken)
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":         sess.AccessToken,
		"user":                 toUserJSON(sess.User),
		"must_change_password": sess.MustChange,
	})
}

func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	if !s.refreshLimiter.allow("ip:" + clientIP(r)) {
		writeProblem(w, http.StatusTooManyRequests, "Too many requests", "")
		return
	}
	token := s.readRefreshCookie(r)
	if token == "" {
		writeProblem(w, http.StatusUnauthorized, "No session", "")
		return
	}
	sess, err := s.svc.Refresh(r.Context(), token)
	if err != nil {
		s.clearRefreshCookie(w)
		writeProblem(w, http.StatusUnauthorized, "Session expired", "")
		return
	}
	s.setRefreshCookie(w, sess.RefreshToken)
	writeJSON(w, http.StatusOK, map[string]any{"access_token": sess.AccessToken})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if token := s.readRefreshCookie(r); token != "" {
		if err := s.svc.Logout(r.Context(), token); err != nil {
			writeProblem(w, http.StatusInternalServerError, "Logout failed", "")
			return
		}
	}
	s.clearRefreshCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) currentUser(w http.ResponseWriter, r *http.Request) (store.User, bool) {
	id, ok := userIDFrom(r.Context())
	if !ok {
		writeProblem(w, http.StatusUnauthorized, "Invalid token subject", "")
		return store.User{}, false
	}
	u, err := s.svc.GetUser(r.Context(), id)
	if err != nil {
		writeProblem(w, http.StatusUnauthorized, "Unknown user", "")
		return store.User{}, false
	}
	return u, true
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	if u, ok := s.currentUser(w, r); ok {
		writeJSON(w, http.StatusOK, toUserJSON(u))
	}
}

func (s *Server) handleUpdateMe(w http.ResponseWriter, r *http.Request) {
	u, ok := s.currentUser(w, r)
	if !ok {
		return
	}
	var body struct {
		DisplayName string `json:"display_name"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if body.DisplayName == "" {
		writeProblem(w, http.StatusBadRequest, "display_name is required", "")
		return
	}
	updated, err := s.svc.UpdateProfile(r.Context(), u.ID, body.DisplayName)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "Update failed", "")
		return
	}
	writeJSON(w, http.StatusOK, toUserJSON(updated))
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	u, ok := s.currentUser(w, r)
	if !ok {
		return
	}
	var body struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if len(body.NewPassword) < 12 {
		writeProblem(w, http.StatusBadRequest, "Password too short", "At least 12 characters.")
		return
	}
	keep := s.svc.CurrentSessionID(r.Context(), s.readRefreshCookie(r))
	err := s.svc.ChangePassword(r.Context(), u.ID, body.CurrentPassword, body.NewPassword, keep)
	switch {
	case errors.Is(err, service.ErrInvalidCredentials):
		writeProblem(w, http.StatusUnauthorized, "Wrong current password", "")
	case err != nil:
		writeProblem(w, http.StatusInternalServerError, "Password change failed", "")
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	u, ok := s.currentUser(w, r)
	if !ok {
		return
	}
	current := s.svc.CurrentSessionID(r.Context(), s.readRefreshCookie(r))
	sessions, err := s.svc.ListSessions(r.Context(), u.ID, current)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "Could not list sessions", "")
		return
	}
	type sessionJSON struct {
		ID         string  `json:"id"`
		DeviceName *string `json:"device_name"`
		IssuedAt   string  `json:"issued_at"`
		ExpiresAt  string  `json:"expires_at"`
		Current    bool    `json:"current"`
	}
	out := make([]sessionJSON, 0, len(sessions))
	for _, sess := range sessions {
		out = append(out, sessionJSON{
			ID:         sess.ID.String(),
			DeviceName: sess.DeviceName,
			IssuedAt:   sess.IssuedAt.UTC().Format(time.RFC3339),
			ExpiresAt:  sess.ExpiresAt.UTC().Format(time.RFC3339),
			Current:    sess.Current,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": out})
}

func (s *Server) handleRevokeSession(w http.ResponseWriter, r *http.Request) {
	u, ok := s.currentUser(w, r)
	if !ok {
		return
	}
	sessionID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "Malformed session id", "")
		return
	}
	switch err := s.svc.RevokeSession(r.Context(), u.ID, sessionID); {
	case errors.Is(err, service.ErrNotFound):
		writeProblem(w, http.StatusNotFound, "No such session", "")
	case err != nil:
		writeProblem(w, http.StatusInternalServerError, "Revoke failed", "")
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func validRole(role string) bool {
	return role == store.RoleAdmin || role == store.RoleMember
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
		Role        string `json:"role"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if body.Username == "" || body.DisplayName == "" || !validRole(body.Role) {
		writeProblem(w, http.StatusBadRequest, "Invalid user fields",
			"username, display_name, and role (admin|member) are required.")
		return
	}
	u, temp, err := s.svc.CreateUser(r.Context(), body.Username, body.DisplayName, body.Role)
	switch {
	case errors.Is(err, service.ErrDuplicateUsername):
		writeProblem(w, http.StatusConflict, "Username already taken", "")
		return
	case err != nil:
		writeProblem(w, http.StatusInternalServerError, "Create failed", "")
		return
	}
	resp := struct {
		userJSON
		TemporaryPassword string `json:"temporary_password"`
	}{toUserJSON(u), temp}
	writeJSON(w, http.StatusCreated, resp)
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.svc.ListUsers(r.Context())
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "Could not list users", "")
		return
	}
	out := make([]userJSON, 0, len(users))
	for _, u := range users {
		out = append(out, toUserJSON(u))
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": out})
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "Malformed user id", "")
		return
	}
	var body struct {
		DisplayName *string `json:"display_name"`
		Role        *string `json:"role"`
		Status      *string `json:"status"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if body.Role != nil && !validRole(*body.Role) {
		writeProblem(w, http.StatusBadRequest, "Invalid role", "")
		return
	}
	if body.Status != nil && *body.Status != store.StatusActive && *body.Status != store.StatusDisabled {
		writeProblem(w, http.StatusBadRequest, "Invalid status", "")
		return
	}
	u, err := s.svc.UpdateUser(r.Context(), service.UpdateUserParams{
		ID: id, DisplayName: body.DisplayName, Role: body.Role, Status: body.Status,
	})
	switch {
	case errors.Is(err, service.ErrNotFound):
		writeProblem(w, http.StatusNotFound, "No such user", "")
	case err != nil:
		writeProblem(w, http.StatusInternalServerError, "Update failed", "")
	default:
		writeJSON(w, http.StatusOK, toUserJSON(u))
	}
}

func (s *Server) handleResetPassword(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "Malformed user id", "")
		return
	}
	temp, err := s.svc.ResetPassword(r.Context(), id)
	switch {
	case errors.Is(err, service.ErrNotFound):
		writeProblem(w, http.StatusNotFound, "No such user", "")
	case err != nil:
		writeProblem(w, http.StatusInternalServerError, "Reset failed", "")
	default:
		writeJSON(w, http.StatusOK, map[string]string{"temporary_password": temp})
	}
}
