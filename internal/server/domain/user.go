package domain

import (
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID         uuid.UUID `json:"id"`
	Email      string `json:"email"`
	SecretHash string `json:"secret_hash"`
	CreatedAt  time.Time `json:"created_at"`
}

var emailRegex = regexp.MustCompile(`^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$`)
var phcRegex = regexp.MustCompile(`^\$[a-z0-9-]+\$v=\d+\$[a-zA-Z0-9-,=]+\$[A-Za-z0-9+/=_-]+\$[A-Za-z0-9+/=_-]+$`)

func NewUser(email string, secretHash string) (*User, error) {
	if email == "" {
		return nil, ErrMissingEmail
	}
	if !emailRegex.MatchString(email) {
		return nil, ErrInvalidEmail
	}
	if strings.TrimSpace(secretHash) == "" {
		return nil, ErrMissingSecretHash
	}

	if !phcRegex.MatchString(secretHash) {
		return nil, ErrInvalidPHCFormat
	}

	id := uuid.New()

	return &User{
		ID:			id,
		Email:      email,
		SecretHash: secretHash,
	}, nil
}