// Package auth defines how the server authenticates connecting clients.
//
// The Authenticator interface is intentionally the only thing the server
// package depends on, so the auth mechanism can be swapped (mTLS, per-client
// keypairs, JWT, etc.) without touching server or protocol code. v1 ships
// one implementation: a shared bearer token.
package auth

import "context"

// Identity describes an authenticated client.
type Identity struct {
	// ClientName is the name the client reported. Not trusted for
	// authorization decisions by itself, only for logging - the token
	// (or whatever credential was used) is what actually gates access.
	ClientName string
}

// Authenticator validates a credential presented by a connecting client.
// Implementations must be safe for concurrent use.
type Authenticator interface {
	// Authenticate checks the given token/credential string. It returns
	// the resulting Identity on success, or an error describing why
	// authentication failed. The error message may be sent back to the
	// client, so it must not leak secrets.
	Authenticate(ctx context.Context, credential string, clientName string) (Identity, error)
}
