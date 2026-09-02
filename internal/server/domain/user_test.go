package domain

import (
	"testing"

	"github.com/google/uuid"
)

func TestNewUser(t *testing.T) {
	email := "user@example.com"
	secretHash := "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$qU31Xy16pI36O6H0Xb1sW5vK1c7O5Y2X"

	tests := []struct {
		name       string
		email      string
		secretHash string
		expectedErr error
	}{
		{
			name:       "Success_Valid_User",
			email:      email,
			secretHash: secretHash,
			expectedErr: nil,
		},
		{
			name:       "Failure_Missing_Email",
			email:      "",
			secretHash: secretHash,
			expectedErr: ErrMissingEmail,
		},
		{
			name:       "Failure_Invalid_Email",
			email:      "userexample",
			secretHash: secretHash,
			expectedErr: ErrInvalidEmail,
		},
		{
			name:       "Failure_Missing_Hash",
			email:      "user@example.com",
			secretHash: "", 
			expectedErr: ErrMissingSecretHash,
		},
		{
			name:       "Failure_Invalid_Hash",
			email:      email,
			secretHash: "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ",
			expectedErr: ErrInvalidPHCFormat,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, err := NewUser(tt.email, tt.secretHash)

			// Verify expected error
			if err != tt.expectedErr {
				t.Errorf("expected error %v, got %v", tt.expectedErr, err)
			}

			// Verify success fields
			if tt.expectedErr == nil {

				// Check fields
				if user.ID == uuid.Nil {
					t.Errorf("Expected id population, got uuid.Nil")
				}

				if user.Email != tt.email {
					t.Errorf("expected email %s, got %s", tt.email, user.Email)
				}
				
				if user.SecretHash != tt.secretHash {
					t.Errorf("Expected secret hash %s, got %s", tt.secretHash, user.SecretHash)
				} 
			}
		})
	}
}