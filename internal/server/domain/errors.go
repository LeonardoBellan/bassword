package domain

import "errors"

var (
	// Domain
	ErrMissingEmail = errors.New("missing email")
	ErrInvalidEmail = errors.New("invalid email format")
	ErrMissingSecretHash = errors.New("missing secret hash")
	ErrInvalidPHCFormat = errors.New("invalid PHC format")

	ErrEmptyServiceName = errors.New("service name cannot be empty")
	ErrEmptyEncryptedData = errors.New("encrypted data cannot be empty")
	ErrInvalidUserID = errors.New("Invalid userID format")
	
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