package domain

import (
	"testing"
	"bytes"

	"github.com/google/uuid"
)

func TestNewCredentials(t *testing.T) {

	userID := uuid.New()
	serviceIndex := []byte("example-service-index")
	serviceEncrypted := []byte("example-service-encrypted")
	payloadEncrypted := []byte("encrypted-bytes")

	tests := []struct {
		name          string
		userID        uuid.UUID
		serviceIndex []byte
		serviceEncrypted []byte
		payloadEncrypted []byte
		expectedErr   error
	}{
		{
			name:          "Success_Valid_Credentials",
			userID:        userID,
			serviceIndex:   serviceIndex,
			serviceEncrypted: serviceEncrypted,
			payloadEncrypted: payloadEncrypted,
			expectedErr:   nil,
		},
		{
			name:          "Failure_Empty_Service_Name_Index",
			userID:        userID,
			serviceIndex:   nil,
			serviceEncrypted: serviceEncrypted,
			payloadEncrypted: payloadEncrypted,
			expectedErr: ErrEmptyServiceIndex,
		},
		{
			name:          "Failure_Empty_Service_Encrypted",
			userID:        userID,
			serviceIndex:   serviceIndex,
			serviceEncrypted: nil,
			payloadEncrypted: payloadEncrypted,
			expectedErr:   ErrEmptyServiceEncrypted,
		},
		{
			name:          "Failure_Empty_Payload",
			userID:        userID,
			serviceIndex: serviceIndex,
			serviceEncrypted: serviceEncrypted,
			payloadEncrypted: nil,
			expectedErr:   ErrEmptyPayload,
		},{
			name:          "Failure_UserID_Nil",
			userID:        uuid.Nil,
			serviceIndex:   serviceIndex,
			serviceEncrypted: serviceEncrypted,
			payloadEncrypted: payloadEncrypted,
			expectedErr:   ErrInvalidUserID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			creds, err := NewCredentials(tt.userID, tt.serviceIndex, tt.serviceEncrypted, tt.payloadEncrypted)

			if err != tt.expectedErr {
				t.Errorf("expected error %v, got %v", tt.expectedErr, err)
			}

			if tt.expectedErr == nil {
				
				// Check fields
				if creds.ID == uuid.Nil {
					t.Errorf("Expected id population, got uuid.Nil")
				}

				if creds.UserID != tt.userID {
					t.Errorf("expected userID %s, got %s", tt.userID, creds.UserID)
				}
				if !bytes.Equal(creds.ServiceIndex, tt.serviceIndex) {
					t.Errorf("ServiceIndex mismatch")
				}
				if !bytes.Equal(creds.ServiceEncrypted, tt.serviceEncrypted) {
					t.Errorf("ServiceIndex mismatch")
				}
				if !bytes.Equal(creds.PayloadEncrypted, tt.payloadEncrypted) {
					t.Errorf("ServiceIndex mismatch")
				}
			}
		})
	}
}
