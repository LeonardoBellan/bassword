package domain

import (
	"testing"
	"bytes"

	"github.com/google/uuid"
)

func TestNewCredentials(t *testing.T) {

	userID := uuid.New()
	serviceNameIndex := []byte("example-service")
	encryptedData := []byte("encrypted-bytes")

	tests := []struct {
		name          string
		userID        uuid.UUID
		serviceNameIndex []byte
		encryptedData []byte
		expectedErr   error
	}{
		{
			name:          "Success_Valid_Credentials",
			userID:        userID,
			serviceNameIndex:   serviceNameIndex,
			encryptedData: encryptedData,
			expectedErr:   nil,
		},
		{
			name:          "Failure_Empty_Service_Name_Index",
			userID:        userID,
			serviceNameIndex:   nil,
			encryptedData: encryptedData,
			expectedErr:   ErrEmptyServiceNameIndex,
		},
		{
			name:          "Failure_Empty_Encrypted_Data",
			userID:        userID,
			serviceNameIndex: serviceNameIndex,
			encryptedData: nil,
			expectedErr:   ErrEmptyEncryptedData,
		},{
			name:          "Failure_UserID_Nil",
			userID:        uuid.Nil,
			serviceNameIndex:   serviceNameIndex,
			encryptedData: encryptedData,
			expectedErr:   ErrInvalidUserID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			creds, err := NewCredentials(tt.userID, tt.serviceNameIndex, tt.encryptedData)

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
				if !bytes.Equal(creds.ServiceNameIndex, tt.serviceNameIndex) {
					t.Errorf("ServiceNameIndex mismatch")
				}
				if !bytes.Equal(creds.EncryptedData, tt.encryptedData) {
					t.Errorf("ServiceNameIndex mismatch")
				}
			}
		})
	}
}
