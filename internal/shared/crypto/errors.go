package crypto

import "errors"

var (
	// Crypto
	ErrMismatchedSecret = errors.New("given secret does not match")
	ErrInvalidToken = errors.New("invalid token format")
)