package domain

import (
	"time"

	"github.com/google/uuid"
)

type Credentials struct {
	ID            uuid.UUID	`json:"id"`
	UserID        uuid.UUID	`json:"user_id"`
	ServiceNameIndex  	[]byte    `json:"service_name"`	
	EncryptedData []byte    `json:"encrypted_data"`
	CreatedAt     time.Time `json:"created_at"`
}

func NewCredentials(userID uuid.UUID, serviceNameIndex []byte, encryptedData []byte) (*Credentials,error) {

	if userID == uuid.Nil {
        return nil, ErrInvalidUserID
    }
	if len(serviceNameIndex) <= 0 {
		return nil, ErrEmptyServiceNameIndex
	}
	if len(encryptedData) <= 0 {
		return nil, ErrEmptyEncryptedData
	}

	id := uuid.New()

	return &Credentials{
		ID: id,
		UserID: userID,
		ServiceNameIndex: serviceNameIndex,
		EncryptedData: encryptedData,
	}, nil
}
