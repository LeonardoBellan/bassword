package domain

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID         string `json:"id"`
	Email      string `json:"email"`
	ServerHash []byte `json:"server_hash"`
	ServerSalt []byte `json:"server_salt"`
	CreatedAt  time.Time `json:"created_at"`
}

func NewUser(email string, serverHash, serverSalt []byte) (*User, error) {
	if email == "" {
		return nil, ErrInvalidEmail
	}
	if len(serverHash) == 0 {
		return nil, ErrEmptyHash
	}
	if len(serverSalt) == 0 {
		return nil, ErrEmptySalt
	}

	id := uuid.NewString()

	return &User{
		ID:			id,
		Email:      email,
		ServerHash: serverHash,
		ServerSalt: serverSalt,
	}, nil
}