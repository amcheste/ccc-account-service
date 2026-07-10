# CLAUDE.md

This file is read by Claude Code at the start of every session in this repo.

---

## About This Repo

Go microservice providing identity for the Command and Control Center
(CCC) homelab platform: username/password login, Ed25519 JWT issuance,
rotated refresh tokens, and household roles (admin/member). Runs on a
mixed arm64/amd64 k8s cluster (Raspberry Pi 5 + x86).

The approved design is `docs/design/account-service.md`. Read it before
structural changes, and update it in the same PR when a decision
changes.

Rules that matter here:

- CGO stays disabled. The multi-arch image cross-compiles for
  linux/arm64 + linux/amd64; a CGO dependency breaks the build. Pick
  pure-Go libraries (pgx, x/crypto/argon2, modernc-style deps).
- Business logic lives in `internal/service`. Transport packages
  (`internal/httpserver`, `internal/grpcserver`) are thin adapters and
  never touch the store directly.
- gRPC contracts come from `github.com/amcheste/ccc-protos/gen/go` at
  a tagged release. Never define cross-service protos in this repo.
- `deploy/base/` is a generic kustomize base. Anything
  cluster-specific (namespaces, image pins, secrets, ingress) belongs
  in the private ccc-deploy repo, not here.
- Secrets never appear in code, config defaults, or tests. They arrive
  as env vars from k8s Secrets.

---

## Developer Preferences

### Editor
- Primary: Vim
- AI editor: Cursor

### Shell
- zsh, minimal prompt

### Git & GitHub Workflow
- **Branch model:** `main` = latest release. `develop` = integration branch.
- Always branch from `develop`, never commit directly
- PRs always target `develop`
- `main` is only updated via CLI merge (`git merge --no-ff origin/develop`) by `/publish-release` — **never via a GitHub PR**. GitHub's merge button squash-merges by default, dropping ancestry and causing conflicts on the next release.
- Conventional commits: `feat:`, `fix:`, `docs:`, `chore:`

### Scripting Standards
- Shell scripts must pass `shellcheck`
- Use `set -euo pipefail`
- Scripts should be idempotent

---

## Brand

This repo descends from [`amcheste/repo-template`](https://github.com/amcheste/repo-template), which is brand-aligned with [`@amcheste/brand`](https://github.com/amcheste/alanchester-brand). Badge colors (Hunter Green `#1F4D3A`, Ink `#0B0B0C`) match the brand by default.

When generating prose, follow the brand voice rules at [`voice.md`](https://github.com/amcheste/alanchester-brand/blob/main/docs/voice.md): no em dashes in prose, calibrated hedges over weak ones, lowercase eyebrows, numerical specificity. Hunter green is reserved for data, pivots, and the δ; don't use it as decoration.

For deeper brand integration (palette adoption, mark embedding, full theming sweep), paste [`docs/theming-prompt.md`](https://github.com/amcheste/alanchester-brand/blob/main/docs/theming-prompt.md) from the brand repo into a Claude Code session in this repo.

---

## Learned Preferences

<!-- Claude Code will suggest additions here as patterns emerge across sessions -->
