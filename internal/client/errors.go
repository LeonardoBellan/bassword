package client

import "errors"

var (
	ErrUnauthorized = errors.New("authentication failed")
	ErrNotRegistered = errors.New("missing email")
)