package domain

import (
	"testing"

	"github.com/google/uuid"
)

func TestNewCredentials(t *testing.T) {
	tests := []struct {
		name          string
		userID        string
		serviceName   string
		encryptedData []byte
		expectedErr   error
	}{
		{
			name:          "Success_Valid_Credentials",
			userID:        "123e4567-e89b-12d3-a456-426614174000",
			serviceName:   "example-service",
			encryptedData: []byte("encrypted-bytes"),
			expectedErr:   nil,
		},
		{
			name:          "Failure_Empty_Service_Name",
			userID:        "123e4567-e89b-12d3-a456-426614174000",
			serviceName:   "",
			encryptedData: []byte("encrypted-bytes"),
			expectedErr:   ErrEmptyServiceName,
		},
		{
			name:          "Failure_Empty_Encrypted_Data",
			userID:        "123e4567-e89b-12d3-a456-426614174000",
			serviceName:   "example-service",
			encryptedData: nil,
			expectedErr:   ErrEmptyEncryptedData,
		},
		{
			name:          "Failure_Invalid_UserID",
			userID:        "",
			serviceName:   "example-service",
			encryptedData: []byte("encrypted-bytes"),
			expectedErr:   ErrMissingUserID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			creds, err := NewCredentials(tt.userID, tt.serviceName, tt.encryptedData)

			if err != tt.expectedErr {
				t.Errorf("expected error %v, got %v", tt.expectedErr, err)
			}

			if tt.expectedErr == nil {

				// Check ID
				if creds.ID == "" {
					t.Error("failure generating ID, got empty string")
				}

				if _, err := uuid.Parse(creds.ID); err != nil {
                    t.Errorf("expected a valid UUID format for ID, got %s (error: %v)", creds.ID, err)
                }

				// Check fields
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