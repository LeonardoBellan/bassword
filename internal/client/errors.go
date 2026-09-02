package client

import "errors"

var (
	ErrUnauthorized = errors.New("authentication failed")
	ErrMissingEmail = errors.New("missing email")
)