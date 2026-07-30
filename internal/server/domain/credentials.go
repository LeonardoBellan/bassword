package domain

import (
	"time"

	"github.com/google/uuid"
)

type Credentials struct {
	ID            uuid.UUID	`json:"id"`
	UserID        uuid.UUID	`json:"user_id"`
	ServiceName   string    `json:"service_name"`	
	EncryptedData []byte    `json:"encrypted_data"`
	CreatedAt     time.Time `json:"created_at"`
}

func NewCredentials(userID uuid.UUID, serviceName string, encryptedData []byte) (*Credentials,error) {

	if userID == uuid.Nil {
        return nil, ErrInvalidUserID
    }
	if serviceName == "" {
		return nil, ErrEmptyServiceName
	}
	if len(encryptedData) <= 0 {
		return nil, ErrEmptyEncryptedData
	}

	id := uuid.New()

	return &Credentials{
		ID: id,
		UserID: userID,
		ServiceName: serviceName,
		EncryptedData: encryptedData,
	}, nil
}