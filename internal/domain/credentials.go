package domain

import (
	"time"
)

type Credentials struct {
	ID            int       `json:"id"`
	UserID        int    	`json:"user_id"`
	ServiceName   string    `json:"service_name"`	
	EncryptedData []byte    `json:"encrypted_data"` // Nonce + Username + Password
	CreatedAt     time.Time `json:"created_at"`
}
func (c *Credentials) IsValid() bool{
	return c.ServiceName != "" || len(c.EncryptedData) > 0 || c.UserID > 0
}