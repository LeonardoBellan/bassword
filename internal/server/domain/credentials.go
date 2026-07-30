package domain

import (
	"time"

	"github.com/google/uuid"
)

type Credentials struct {
	ID            string	`json:"id"`
	UserID        string	`json:"user_id"`
	ServiceName   string    `json:"service_name"`	
	EncryptedData []byte    `json:"encrypted_data"`
	CreatedAt     time.Time `json:"created_at"`
}

func NewCredentials(userID string, serviceName string, encryptedData []byte) (*Credentials,error) {
	if userID == "" {
		return nil, ErrInvalidUserID
	}
	
	if err := uuid.Validate(userID); err != nil {
		return nil, ErrInvalidUserID
	}
	if serviceName == "" {
		return nil, ErrEmptyServiceName
	}
	if len(encryptedData) <= 0 {
		return nil, ErrEmptyEncryptedData
	}

	id := uuid.NewString()

	return &Credentials{
		ID: id,
		UserID: userID,
		ServiceName: serviceName,
		EncryptedData: encryptedData,
	}, nil
}