package models

import "time"

type CredentialEntry struct {
	ID            int       `json:"id"`
	ServiceName   string    `json:"service_name"`
	Username      string    `json:"username"`
	EncryptedData []byte    `json:"encrypted_data"` // Nonce + Ciphertext
	Salt          []byte    `json:"salt"`
	CreatedAt     time.Time `json:"created_at"`
}