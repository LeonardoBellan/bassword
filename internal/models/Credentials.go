package models

import "time"

type Credentials struct {
	ID            int       `json:"id"`
	UserID        int    `json:"user_id"`
	ServiceName   string    `json:"service_name"`	
	EncryptedData []byte    `json:"encrypted_data"` // Nonce + Username + Password
	CreatedAt     time.Time `json:"created_at"`
}
