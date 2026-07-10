// Package service holds the transport-agnostic business logic of the
// account service: user lifecycle, login, token issuance and rotation,
// and session management. Both the REST and gRPC layers call into this
// package; neither transport reaches the store directly.
package service
