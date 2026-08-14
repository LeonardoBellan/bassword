package domain

import (
	"time"

	"github.com/google/uuid"
)

type Credentials struct {
	ID            uuid.UUID	`json:"id"`
	UserID        uuid.UUID	`json:"user_id"`
	ServiceIndex   []byte 	`json:"service_name_index"`
	ServiceEncrypted []byte `json:"service_name_encrypted"`
	PayloadEncrypted []byte `json:"payload_encrypted"`
	CreatedAt     time.Time `json:"created_at"`
}

func NewCredentials(userID uuid.UUID, serviceIndex, serviceEncrypted, payload []byte) (*Credentials,error) {

	if userID == uuid.Nil {
  	return nil, ErrInvalidUserID
  }
	if len(serviceIndex) <= 0 {
		return nil, ErrEmptyServiceIndex
	}
	if len(serviceEncrypted) <= 0 {
		return nil, ErrEmptyServiceEncrypted
	}
	if len(payload) <= 0 {
		return nil, ErrEmptyPayload
	}

	id := uuid.New()

	return &Credentials{
		ID: id,
		UserID: userID,
		ServiceIndex: serviceIndex,
		ServiceEncrypted: serviceEncrypted,
		PayloadEncrypted: payload,
	}, nil
}
