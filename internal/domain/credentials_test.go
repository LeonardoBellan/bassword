package domain

import "testing"

func TestNewCredentials(t *testing.T) {
	tests := []struct {
		name          string
		userID        int
		serviceName   string
		encryptedData []byte
		expectedErr   error
	}{
		{
			name:          "Success_Valid_Credentials",
			userID:        1,
			serviceName:   "example-service",
			encryptedData: []byte("encrypted-bytes"),
			expectedErr:   nil,
		},
		{
			name:          "Failure_Empty_Service_Name",
			userID:        1,
			serviceName:   "",
			encryptedData: []byte("encrypted-bytes"),
			expectedErr:   ErrEmptyServiceName,
		},
		{
			name:          "Failure_Empty_Encrypted_Data",
			userID:        1,
			serviceName:   "example-service",
			encryptedData: nil,
			expectedErr:   ErrEmptyEncryptedData,
		},
		{
			name:          "Failure_Invalid_UserID",
			userID:        0,
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
				if creds.UserID != tt.userID {
					t.Errorf("expected userID %d, got %d", tt.userID, creds.UserID)
				}
				if creds.ServiceName != tt.serviceName {
					t.Errorf("expected serviceName %s, got %s", tt.serviceName, creds.ServiceName)
				}
			}
		})
	}
}