// Package auth implements the cryptographic core of the account
// service: argon2id password hashing (OWASP-minimum parameters sized
// for Pi-class nodes), Ed25519 JWT mint and verify, JWKS publication,
// and refresh-token rotation with reuse detection.
package auth
