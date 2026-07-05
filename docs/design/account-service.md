# Account Service design

Status: approved 2026-07-03. This is the reviewed design the skeleton
follows; deviations should update this doc in the same PR.

## 1. Scope

The account service owns identity and nothing else: user lifecycle,
credentials, login, JWT issuance, refresh tokens with rotation and
revocation, and the coarse household roles (`admin`, `member`) encoded
into token claims.

Explicitly out of scope, reserved for future services:

- Fine-grained authorization. Services check the `roles` claim; a
  policy service can be added later without touching this one.
- Audit. Security events are structured log lines (stable `event=`
  field) a future audit service can consume.
- SSO/OIDC. Not in v1, but credentials live in their own table, tokens
  are standard JWTs with a JWKS endpoint, and login is isolated in one
  REST handler, so adding it later is contained.

## 2. Data model

PostgreSQL, one shared CloudNativePG cluster for the homelab, dedicated
`account` database and role for this service. Postgres over SQLite
because SQLite pins the service to one replica and one PVC; the ops
cost of Postgres is paid once and reused by every later service. The
Postgres pods prefer amd64 nodes via nodeSelector; the Go services run
anywhere.

```
users
  id            uuid PK (v7)
  username      citext UNIQUE NOT NULL
  display_name  text NOT NULL
  email         text NULL             -- unused in v1, kept for later
  role          text CHECK (role IN ('admin','member'))
  status        text CHECK (status IN ('active','disabled'))
  created_at / updated_at timestamptz

credentials
  user_id       uuid PK -> users.id
  kind          text DEFAULT 'password'   -- future: 'oidc', 'passkey'
  password_hash text NOT NULL             -- PHC string, params embedded
  updated_at    timestamptz

refresh_tokens
  id            uuid PK
  user_id       uuid -> users.id
  token_hash    bytea NOT NULL            -- SHA-256; raw token never stored
  device_name   text NULL
  issued_at / expires_at timestamptz
  revoked_at    timestamptz NULL
  replaced_by   uuid NULL                 -- rotation chain, reuse detection
```

Deliberate simplifications: no households table (single implicit
household, `role` is a user column), no permissions table, no open
registration, no email/SMTP (password reset is admin-issued temp
password with forced change). Migrations are plain SQL run by
golang-migrate at startup.

## 3. API

One binary, two listeners, shared service core. REST (:8080) for the
web frontend, gRPC (:9090) for other services, ops (:8081) for probes
and metrics. No separate BFF and no grpc-gateway: the external surface
is auth-shaped (cookies, credentials, rate limits) and hand-written
handlers over the same service layer stay simpler at this scale.

The REST listener serves under a configurable base path
(`CCC_HTTP_BASE_PATH`, e.g. `/api/account`). The ingress routes by
prefix without rewriting, so cookie Path attributes and redirects
always match what the browser sees; path rewrites at the ingress are
the classic source of broken auth cookies and are banned platform-wide.

The gRPC contract lives in `ccc-protos` (`ccc.account.v1`):
`ValidateToken`, `GetUser`, `ListUsers`, `GetUserRoles`. Other services
default to local JWT verification against the JWKS endpoint; the
10-minute access token TTL bounds the revocation window. `ValidateToken`
exists for endpoints that cannot tolerate that window.

REST surface: `POST /v1/auth/login|refresh|logout`, `GET|PATCH /v1/me`,
`PUT /v1/me/password`, `GET|DELETE /v1/me/sessions`, admin-only
`POST|GET|PATCH /v1/users` and `POST /v1/users/{id}/reset-password`,
plus `GET /.well-known/jwks.json`. Errors are RFC 7807 problem+json.
Login and refresh get in-process per-username and per-IP rate limits.

## 4. Auth and security

- Password hashing: argon2id (`golang.org/x/crypto/argon2`), m=19 MiB,
  t=2, p=1, roughly 40 to 80 ms on a Pi 5. A semaphore caps concurrent
  hashes at 4 so worst-case memory stays inside the pod limit. Params
  live in the PHC hash string, so raising them later is a lazy rehash
  on next login.
- Access token: Ed25519-signed JWT, 10 minute TTL. Claims: `iss`,
  `sub`, `aud`, `exp`, `iat`, `jti`, `preferred_username`, `roles`.
  JWKS endpoint publishes public keys with `kid`; rotation is manual
  (add key, sign with new, drop old after max TTL).
- Refresh token: opaque 256-bit random, 30 day sliding TTL, rotated on
  every use. Presenting an already-replaced token revokes the whole
  chain (stolen-token tripwire). Revocable per session or in bulk.
- No JWT denylist. The short TTL is the revocation window.
- Secrets: Bitnami sealed-secrets. Encrypted secrets live in the
  private ccc-deploy repo. Back up the controller key off-cluster.

## 5. Kubernetes

Namespace `ccc`. Stateless Deployment, 2 replicas, no node pinning
(only Postgres prefers amd64). Requests 50m/64Mi, limits 500m/256Mi;
the memory limit is sized around the argon2id budget. Liveness is
process-only `/healthz`; readiness `/readyz` includes a DB ping.
Discovery is plain CoreDNS (`account-service.ccc.svc:9090`). No service
mesh and no intra-cluster mTLS in v1.

Images are static Go binaries (CGO_ENABLED=0) on distroless/static,
built as multi-arch manifests (linux/arm64 + linux/amd64) via buildx.

## 6. Repo topology

- `ccc-account-service` (public): this repo. Code, Dockerfile, CI, and
  a generic kustomize base under `deploy/base/` with no cluster
  specifics.
- `ccc-protos` (public): buf-managed contracts, committed Go codegen
  consumed as a tagged module.
- `ccc-deploy` (private): kustomize overlays referencing the public
  base, sealed secrets, namespaces, CNPG config, everything
  cluster-specific. The dependency arrow only points private to
  public. Rule of thumb: if a value would change when someone else
  deployed this, it lives in ccc-deploy.

Layout: `cmd/account-service` wires config and listeners;
`internal/service` holds business logic; `internal/store` (pgx +
migrations), `internal/auth` (hashing, JWT, rotation),
`internal/grpcserver` and `internal/httpserver` are thin adapters.
No `pkg/`: shared contracts live in ccc-protos.

## 7. Testing and observability

Unit tests concentrate on `internal/service` and `internal/auth`
against an in-memory store fake. `internal/store` gets integration
tests via testcontainers-go behind a build tag. Contract safety comes
from `buf breaking` in ccc-protos CI. Logging is slog JSON to stdout;
metrics are Prometheus on the ops port (request duration/count,
`login_attempts_total{result}`, `active_refresh_tokens`). No tracing
in v1.
