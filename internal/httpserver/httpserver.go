// Package httpserver serves the external REST API: login, refresh,
// logout, profile, sessions, and admin user management. Errors follow
// RFC 7807 problem+json. It is a thin adapter over the service layer;
// no business logic lives here.
package httpserver

import (
	"net/http"
	"strings"
	"time"

	"github.com/amcheste/ccc-account-service/internal/auth"
	"github.com/amcheste/ccc-account-service/internal/service"
)

// Config carries the transport-level settings.
type Config struct {
	// BasePath prefixes every route (e.g. "/api/account") so the
	// ingress routes by prefix without rewriting (design §3).
	BasePath string
	// CookieSecure sets the Secure attribute on the refresh cookie.
	CookieSecure bool
	// RefreshTTL bounds the refresh cookie's Max-Age.
	RefreshTTL time.Duration
}

// Server holds handler dependencies.
type Server struct {
	svc    *service.Service
	tokens *auth.TokenIssuer
	cfg    Config
	loginLimiter,
	refreshLimiter *rateLimiter
}

// New builds the REST handler tree.
func New(svc *service.Service, tokens *auth.TokenIssuer, cfg Config) http.Handler {
	cfg.BasePath = strings.TrimSuffix(cfg.BasePath, "/")
	s := &Server{
		svc:    svc,
		tokens: tokens,
		cfg:    cfg,
		// Household-scale budgets: generous for humans, hostile to
		// scripts hammering argon2id (design §3, §4).
		loginLimiter:   newRateLimiter(10, time.Minute),
		refreshLimiter: newRateLimiter(60, time.Minute),
	}

	mux := http.NewServeMux()
	b := cfg.BasePath

	mux.HandleFunc("GET "+b+"/.well-known/jwks.json", s.handleJWKS)
	mux.HandleFunc("POST "+b+"/v1/auth/login", s.handleLogin)
	mux.HandleFunc("POST "+b+"/v1/auth/refresh", s.handleRefresh)
	mux.HandleFunc("POST "+b+"/v1/auth/logout", s.handleLogout)

	mux.Handle("GET "+b+"/v1/me", s.requireAuth(s.handleMe))
	mux.Handle("PATCH "+b+"/v1/me", s.requireAuth(s.handleUpdateMe))
	mux.Handle("PUT "+b+"/v1/me/password", s.requireAuth(s.handleChangePassword))
	mux.Handle("GET "+b+"/v1/me/sessions", s.requireAuth(s.handleListSessions))
	mux.Handle("DELETE "+b+"/v1/me/sessions/{id}", s.requireAuth(s.handleRevokeSession))

	mux.Handle("POST "+b+"/v1/users", s.requireAdmin(s.handleCreateUser))
	mux.Handle("GET "+b+"/v1/users", s.requireAdmin(s.handleListUsers))
	mux.Handle("PATCH "+b+"/v1/users/{id}", s.requireAdmin(s.handleUpdateUser))
	mux.Handle("POST "+b+"/v1/users/{id}/reset-password", s.requireAdmin(s.handleResetPassword))

	return mux
}

const refreshCookie = "ccc_refresh"

// cookiePath scopes the refresh cookie to this service's API only.
func (s *Server) cookiePath() string { return s.cfg.BasePath + "/v1" }

func (s *Server) setRefreshCookie(w http.ResponseWriter, token string) {
	// Secure is config-driven: true everywhere except the plain-http
	// local dev stack (ccc.localhost is a browser secure context).
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // HttpOnly+SameSite set; Secure from config
		Name:     refreshCookie,
		Value:    token,
		Path:     s.cookiePath(),
		MaxAge:   int(s.cfg.RefreshTTL.Seconds()),
		HttpOnly: true,
		Secure:   s.cfg.CookieSecure,
		SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) clearRefreshCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // HttpOnly+SameSite set; Secure from config
		Name:     refreshCookie,
		Value:    "",
		Path:     s.cookiePath(),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.cfg.CookieSecure,
		SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) readRefreshCookie(r *http.Request) string {
	c, err := r.Cookie(refreshCookie)
	if err != nil {
		return ""
	}
	return c.Value
}
