package models

import "time"

type CredentialEntry struct {
	ID            int       `json:"id"`
	ServiceName   string    `json:"service_name"`
	Username      string    `json:"username"`
	EncryptedData []byte    `json:"encrypted_data"` // Nonce + Ciphertext
	CreatedAt     time.Time `json:"created_at"`
}

// CreateCredentialInput represents the data required to create a new stored credential.
type CreateCredentialInput struct {
	ServiceName   string `json:"service_name"`
	Username      string `json:"username"`
	EncryptedData []byte `json:"encrypted_data"` // Nonce + Ciphertext
}