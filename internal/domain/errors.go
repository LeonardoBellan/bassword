package domain

import "errors"

var (
	// Domain
	ErrEmptyServiceName = errors.New("service name cannot be empty")
	ErrEmptyEncryptedData = errors.New("encrypted data cannot be empty")
	ErrMissingUserID = errors.New("user ID must be greater than zero")

	ErrInvalidEmail = errors.New("invalid email format")
	ErrEmptyHash = errors.New("authorization hash cannot be empty")
	ErrEmptySalt = errors.New("user salt cannot be empty")

	// Crypto
	ErrMismatchedSecret = errors.New("given secret does not match")

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