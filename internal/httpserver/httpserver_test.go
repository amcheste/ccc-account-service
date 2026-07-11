package httpserver

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/amcheste/ccc-account-service/internal/auth"
	"github.com/amcheste/ccc-account-service/internal/service"
	"github.com/amcheste/ccc-account-service/internal/store/storetest"
)

const basePath = "/api/account"

func testServer(t *testing.T) (*httptest.Server, *service.Service) {
	t.Helper()
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
	svc := service.New(storetest.New(), hasher, issuer, time.Hour, slog.Default())
	if err := svc.Bootstrap(t.Context(), "alan", "bootstrap-password"); err != nil {
		t.Fatal(err)
	}
	// Clear must_change so most tests use a settled admin account.
	sess, err := svc.Login(t.Context(), "alan", "bootstrap-password", "seed")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ChangePassword(t.Context(), sess.User.ID, "bootstrap-password", "alan-password-12", nil); err != nil {
		t.Fatal(err)
	}

	handler := New(svc, issuer, Config{
		BasePath: basePath, CookieSecure: false, RefreshTTL: time.Hour,
	})
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	return ts, svc
}

type client struct {
	t      *testing.T
	ts     *httptest.Server
	token  string
	cookie *http.Cookie
}

func (c *client) do(method, path string, body any) (*http.Response, []byte) {
	c.t.Helper()
	var reader *bytes.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, c.ts.URL+basePath+path, reader)
	if err != nil {
		c.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if c.cookie != nil {
		req.AddCookie(c.cookie)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(res.Body)
	for _, ck := range res.Cookies() {
		if ck.Name == refreshCookie {
			if ck.MaxAge < 0 {
				c.cookie = nil
			} else {
				c.cookie = &http.Cookie{Name: ck.Name, Value: ck.Value} //nolint:gosec // client-side request cookie
			}
		}
	}
	return res, buf.Bytes()
}

func (c *client) login(username, password string) (*http.Response, []byte) {
	c.t.Helper()
	res, body := c.do("POST", "/v1/auth/login",
		map[string]string{"username": username, "password": password})
	if res.StatusCode == http.StatusOK {
		var parsed struct {
			AccessToken string `json:"access_token"`
		}
		_ = json.Unmarshal(body, &parsed)
		c.token = parsed.AccessToken
	}
	return res, body
}

func TestLoginRefreshLogoutFlow(t *testing.T) {
	ts, _ := testServer(t)
	c := &client{t: t, ts: ts}

	res, body := c.login("alan", "alan-password-12")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("login = %d: %s", res.StatusCode, body)
	}
	var login struct {
		User struct {
			Role string `json:"role"`
		} `json:"user"`
		MustChange bool `json:"must_change_password"`
	}
	_ = json.Unmarshal(body, &login)
	if login.User.Role != "admin" || login.MustChange {
		t.Errorf("login body: %s", body)
	}
	if c.cookie == nil {
		t.Fatal("no refresh cookie set")
	}
	firstCookie := c.cookie.Value

	// Cookie attributes: HttpOnly, scoped to the API.
	res2, _ := c.do("POST", "/v1/auth/refresh", nil)
	if res2.StatusCode != http.StatusOK {
		t.Fatalf("refresh = %d", res2.StatusCode)
	}
	if c.cookie.Value == firstCookie {
		t.Error("refresh did not rotate the cookie")
	}

	res3, _ := c.do("POST", "/v1/auth/logout", nil)
	if res3.StatusCode != http.StatusNoContent {
		t.Fatalf("logout = %d", res3.StatusCode)
	}
	if c.cookie != nil {
		t.Error("logout did not clear the cookie")
	}
}

func TestLoginRejectsBadCredentials(t *testing.T) {
	ts, _ := testServer(t)
	c := &client{t: t, ts: ts}
	res, body := c.login("alan", "wrong")
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad login = %d", res.StatusCode)
	}
	if !strings.Contains(string(body), "Invalid credentials") {
		t.Errorf("problem body: %s", body)
	}
	if ct := res.Header.Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("content type = %s", ct)
	}
}

func TestAuthGates(t *testing.T) {
	ts, _ := testServer(t)
	c := &client{t: t, ts: ts}

	res, _ := c.do("GET", "/v1/me", nil)
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauthenticated /v1/me = %d", res.StatusCode)
	}

	c.token = "garbage"
	res, _ = c.do("GET", "/v1/users", nil)
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("garbage token /v1/users = %d", res.StatusCode)
	}
}

func TestAdminGateBlocksMembers(t *testing.T) {
	ts, _ := testServer(t)
	admin := &client{t: t, ts: ts}
	admin.login("alan", "alan-password-12")

	// Admin creates a member; temp password comes back once.
	res, body := admin.do("POST", "/v1/users",
		map[string]string{"username": "sam", "display_name": "Sam", "role": "member"})
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("create user = %d: %s", res.StatusCode, body)
	}
	var created struct {
		TemporaryPassword string `json:"temporary_password"`
	}
	_ = json.Unmarshal(body, &created)
	if created.TemporaryPassword == "" {
		t.Fatal("no temporary password in create response")
	}

	member := &client{t: t, ts: ts}
	res, body = member.login("sam", created.TemporaryPassword)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("member login = %d: %s", res.StatusCode, body)
	}
	if !strings.Contains(string(body), `"must_change_password":true`) {
		t.Errorf("temp password login should flag must_change: %s", body)
	}

	res, _ = member.do("GET", "/v1/users", nil)
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("member /v1/users = %d, want 403", res.StatusCode)
	}
}

func TestSessionsListMarksCurrentAndRevokes(t *testing.T) {
	ts, _ := testServer(t)
	laptop := &client{t: t, ts: ts}
	laptop.login("alan", "alan-password-12")
	tablet := &client{t: t, ts: ts}
	tablet.login("alan", "alan-password-12")

	res, body := laptop.do("GET", "/v1/me/sessions", nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("sessions = %d", res.StatusCode)
	}
	var parsed struct {
		Sessions []struct {
			ID      string `json:"id"`
			Current bool   `json:"current"`
		} `json:"sessions"`
	}
	_ = json.Unmarshal(body, &parsed)
	// seed session (from testServer) may have been revoked by the
	// password change; expect at least laptop + tablet.
	if len(parsed.Sessions) < 2 {
		t.Fatalf("sessions = %d, want >= 2: %s", len(parsed.Sessions), body)
	}
	var currentID, otherID string
	for _, s := range parsed.Sessions {
		if s.Current {
			currentID = s.ID
		} else {
			otherID = s.ID
		}
	}
	if currentID == "" || otherID == "" {
		t.Fatalf("current/other not distinguished: %s", body)
	}

	res, _ = laptop.do("DELETE", "/v1/me/sessions/"+otherID, nil)
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke = %d", res.StatusCode)
	}
	// The revoked session's refresh must now fail.
	res, _ = tablet.do("POST", "/v1/auth/refresh", nil)
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("revoked session refresh = %d, want 401", res.StatusCode)
	}
}

func TestChangePasswordEndpoint(t *testing.T) {
	ts, _ := testServer(t)
	c := &client{t: t, ts: ts}
	c.login("alan", "alan-password-12")

	res, _ := c.do("PUT", "/v1/me/password",
		map[string]string{"current_password": "alan-password-12", "new_password": "short"})
	if res.StatusCode != http.StatusBadRequest {
		t.Errorf("short password = %d", res.StatusCode)
	}

	res, _ = c.do("PUT", "/v1/me/password",
		map[string]string{"current_password": "alan-password-12", "new_password": "a-brand-new-password"})
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("change password = %d", res.StatusCode)
	}

	// Caller's own session survives (cookie was presented).
	res, _ = c.do("POST", "/v1/auth/refresh", nil)
	if res.StatusCode != http.StatusOK {
		t.Errorf("own session after password change = %d", res.StatusCode)
	}
}

func TestLoginRateLimit(t *testing.T) {
	ts, _ := testServer(t)
	c := &client{t: t, ts: ts}
	var last int
	for i := 0; i < 12; i++ {
		res, _ := c.do("POST", "/v1/auth/login",
			map[string]string{"username": fmt.Sprintf("ghost-%d", i), "password": "x"})
		last = res.StatusCode
	}
	if last != http.StatusTooManyRequests {
		t.Errorf("12th login attempt = %d, want 429", last)
	}
}

func TestJWKSPublished(t *testing.T) {
	ts, _ := testServer(t)
	c := &client{t: t, ts: ts}
	res, body := c.do("GET", "/.well-known/jwks.json", nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("jwks = %d", res.StatusCode)
	}
	var jwks struct {
		Keys []struct {
			Kty string `json:"kty"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwks); err != nil || len(jwks.Keys) != 1 || jwks.Keys[0].Kty != "OKP" {
		t.Errorf("jwks body: %s", body)
	}
}
