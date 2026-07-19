package domain

import "errors"

var (
	// Storage
	ErrDBNotInitialized     = errors.New("storage: database is not initialized")
	ErrDBAlreadyInitialized = errors.New("storage: database is already initialized")

	ErrNotFound = errors.New("storage: record not found")
	ErrConflict = errors.New("storage: record already exist")

	// Service
	ErrInvalidInput = errors.New("service: invalid input provided")

	ErrUserNotFound        = errors.New("service: user not found")
	ErrCredentialsNotFound = errors.New("service: credentials not found")

)