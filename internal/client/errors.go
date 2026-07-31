package client

import "errors"

var (
	ErrUnauthorized = errors.New("authentication failed")
)