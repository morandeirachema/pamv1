package auth

import (
	"context"
	"errors"
)

// ChainAuthenticator tries each authenticator in order and returns the first
// successful Principal. It is used when more than one identity source is
// enabled (e.g. on-prem AD and Entra ID). A source that returns ErrUnauthorized
// is skipped; any other error (network, misconfig) is returned immediately so
// it is not silently masked.
type ChainAuthenticator struct {
	authenticators []Authenticator
}

// NewChain returns a single Authenticator for the given sources: nil for none,
// the sole element for one, or a chain for several.
func NewChain(auths ...Authenticator) Authenticator {
	nonNil := auths[:0]
	for _, a := range auths {
		if a != nil {
			nonNil = append(nonNil, a)
		}
	}
	switch len(nonNil) {
	case 0:
		return nil
	case 1:
		return nonNil[0]
	default:
		return &ChainAuthenticator{authenticators: append([]Authenticator{}, nonNil...)}
	}
}

// Authenticate tries each source in order, returning the first success. An
// ErrUnauthorized from a source is skipped; any other error is returned at once.
func (c *ChainAuthenticator) Authenticate(ctx context.Context, username, password string) (*Principal, error) {
	for _, a := range c.authenticators {
		p, err := a.Authenticate(ctx, username, password)
		if err == nil {
			return p, nil
		}
		if !errors.Is(err, ErrUnauthorized) {
			return nil, err
		}
	}
	return nil, ErrUnauthorized
}
