package httpserver

import (
	"context"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/amcheste/ccc-account-service/internal/auth"
)

type ctxKey int

const claimsKey ctxKey = iota

func claimsFrom(ctx context.Context) auth.Claims {
	c, _ := ctx.Value(claimsKey).(auth.Claims)
	return c
}

func userIDFrom(ctx context.Context) (uuid.UUID, bool) {
	id, err := uuid.Parse(claimsFrom(ctx).Subject)
	return id, err == nil
}

// requireAuth validates the Bearer access token and stashes claims.
func (s *Server) requireAuth(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		token, ok := strings.CutPrefix(header, "Bearer ")
		if !ok || token == "" {
			writeProblem(w, http.StatusUnauthorized, "Missing bearer token", "")
			return
		}
		claims, err := s.tokens.Verify(token)
		if err != nil {
			writeProblem(w, http.StatusUnauthorized, "Invalid or expired token", "")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), claimsKey, claims)))
	})
}

// requireAdmin stacks the admin role check on requireAuth.
func (s *Server) requireAdmin(next http.HandlerFunc) http.Handler {
	return s.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if !slices.Contains(claimsFrom(r.Context()).Roles, "admin") {
			writeProblem(w, http.StatusForbidden, "Admin role required", "")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// rateLimiter is a fixed-window counter per key: simple, in-process,
// and sufficient at household scale (design §3).
type rateLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	counts map[string]int
	reset  time.Time
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{
		limit: limit, window: window,
		counts: map[string]int{}, reset: time.Now().Add(window),
	}
}

func (l *rateLimiter) allow(keys ...string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if time.Now().After(l.reset) {
		l.counts = map[string]int{}
		l.reset = time.Now().Add(l.window)
	}
	for _, k := range keys {
		if l.counts[k] >= l.limit {
			return false
		}
	}
	for _, k := range keys {
		l.counts[k]++
	}
	return true
}

func clientIP(r *http.Request) string {
	// Trust the ingress's X-Forwarded-For head; fall back to the peer.
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if first, _, ok := strings.Cut(xff, ","); ok {
			return strings.TrimSpace(first)
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
