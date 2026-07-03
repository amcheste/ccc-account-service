// Package grpcserver adapts the ccc.account.v1 gRPC contract (from
// github.com/amcheste/ccc-protos/gen/go) onto the service layer. It
// carries no business logic: handlers translate proto messages and
// status codes only.
package grpcserver
