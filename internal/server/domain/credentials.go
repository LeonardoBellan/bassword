package domain

import (
	"time"
)

type Credentials struct {
	ID            int       `json:"id"`
	UserID        int    	`json:"user_id"`
	ServiceName   string    `json:"service_name"`	
	EncryptedData []byte    `json:"encrypted_data"`
	CreatedAt     time.Time `json:"created_at"`
}

func NewCredentials(userID int, serviceName string, encryptedData []byte) (*Credentials,error) {
	if serviceName == "" {
		return nil, ErrEmptyServiceName
	}
	if len(encryptedData) <= 0 {
		return nil, ErrEmptyEncryptedData
	}
	if userID <= 0 {
		return nil, ErrMissingUserID
	}

	return &Credentials{
		UserID: userID,
		ServiceName: serviceName,
		EncryptedData: encryptedData,
	}, nil
}