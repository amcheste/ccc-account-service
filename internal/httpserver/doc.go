// Package httpserver serves the external REST API: login, refresh,
// logout, profile, and admin user management. Errors follow RFC 7807
// problem+json. Like grpcserver, it is a thin adapter over the
// service layer.
package httpserver
