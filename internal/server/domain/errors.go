package domain

import "errors"

var (
	// Domain
	ErrInvalidEmail     = errors.New("invalid email format")
	ErrEmptyHash        = errors.New("authorization hash cannot be empty")
	ErrEmptySalt        = errors.New("user salt cannot be empty")

	ErrEmptyServiceName = errors.New("service name cannot be empty")
	ErrEmptyEncryptedData = errors.New("encrypted data cannot be empty")
	ErrMissingUserID = errors.New("user ID must be greater than zero")
	
	// Storage
	ErrDBNotInitialized     = errors.New("storage: database is not initialized")
	ErrDBAlreadyInitialized = errors.New("storage: database is already initialized")

	ErrNotFound = errors.New("storage: record not found")
	ErrConflict = errors.New("storage: record already exist")

	// Service
	ErrInvalidInput = errors.New("service: invalid input provided")
	ErrUserExists = errors.New("service: user already exists")
	ErrUserNotFound        = errors.New("service: user not found")
	ErrInvalidSecret 	   = errors.New("service: invalid auth_hash provided")
	ErrCredentialsNotFound = errors.New("service: credentials not found")

)