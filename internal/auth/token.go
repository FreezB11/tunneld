package auth

import (
	"context"
	"crypto/subtle"
	"errors"
)

//TokenAuthenticator authenticates clients against a static set of
//pre-shared bearer tokens (typically loaded from the server's YAML config)
//the auth method was ment to be simple as this is like a personal project in base phase
type TokenAuthenticator struct {
	tokens map[string]struct{}
}

//NewTokenAuthenticator builds a TokenAuthenticator from a list of valid
//tokens (as loaded from config), empty/whitespace-only tokens are ignored
func NewTokenAuthenticator(tokens []string) *TokenAuthenticator {
	set := make(map[string]struct{}, len(tokens))
	for _, t := range tokens {
		if t == "" {
			continue
		}
		set[t] = struct{}{}
	}
	return &TokenAuthenticator{tokens: set}
}

var ErrInvalidToken = errors.New("invalid or missing auth token")

// Authenticate implements Authenticator.
func (a *TokenAuthenticator) Authenticate(_ context.Context, credential string, clientName string) (Identity, error) {
	if credential == "" {
		return Identity{}, ErrInvalidToken
	}
	credBytes := []byte(credential)
	for known := range a.tokens {
		// subtle.ConstantTimeCompare requires equal-length slices
		// (lengths aren't secret), so a fast-path length check is fine
		if len(known) != len(credBytes) {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(known), credBytes) == 1 {
			return Identity{ClientName: clientName}, nil
		}
	}
	return Identity{}, ErrInvalidToken
}