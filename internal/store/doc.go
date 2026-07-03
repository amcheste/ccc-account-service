// Package store implements PostgreSQL persistence (pgx) for users,
// credentials, and refresh tokens, plus embedded SQL migrations.
// The service layer depends on interfaces defined here so unit tests
// can substitute an in-memory fake.
package store
