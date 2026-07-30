package domain

import (
	"testing"

	"github.com/google/uuid"
)

func TestNewCredentials(t *testing.T) {

	userID := uuid.New()
	serviceName := "example-service"
	encryptedData := []byte("encrypted-bytes")

	tests := []struct {
		name          string
		userID        uuid.UUID
		serviceName   string
		encryptedData []byte
		expectedErr   error
	}{
		{
			name:          "Success_Valid_Credentials",
			userID:        userID,
			serviceName:   serviceName,
			encryptedData: encryptedData,
			expectedErr:   nil,
		},
		{
			name:          "Failure_Empty_Service_Name",
			userID:        userID,
			serviceName:   "",
			encryptedData: encryptedData,
			expectedErr:   ErrEmptyServiceName,
		},
		{
			name:          "Failure_Empty_Encrypted_Data",
			userID:        userID,
			serviceName:   serviceName,
			encryptedData: nil,
			expectedErr:   ErrEmptyEncryptedData,
		},{
			name:          "Failure_UserID_Nil",
			userID:        uuid.Nil,
			serviceName:   serviceName,
			encryptedData: encryptedData,
			expectedErr:   ErrInvalidUserID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			creds, err := NewCredentials(tt.userID, tt.serviceName, tt.encryptedData)

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
				if creds.ServiceName != tt.serviceName {
					t.Errorf("expected serviceName %s, got %s", tt.serviceName, creds.ServiceName)
				}
			}
		})
	}
}