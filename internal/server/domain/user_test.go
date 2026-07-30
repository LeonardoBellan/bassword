package domain

import (
	"bytes"
	"testing"

	"github.com/google/uuid"
)

func TestNewUser(t *testing.T) {
	tests := []struct {
		name       string
		email      string
		serverHash []byte
		serverSalt []byte
		expectedErr error
	}{
		{
			name:       "Success_Valid_User",
			email:      "user@example.com",
			serverHash: []byte("super-secret-hash"),
			serverSalt: []byte("random-salt"),
			expectedErr: nil,
		},
		{
			name:       "Failure_Empty_Email",
			email:      "",
			serverHash: []byte("super-secret-hash"),
			serverSalt: []byte("random-salt"),
			expectedErr: ErrInvalidEmail,
		},
		{
			name:       "Failure_Empty_Hash",
			email:      "user@example.com",
			serverHash: nil, 
			serverSalt: []byte("random-salt"),
			expectedErr: ErrEmptyHash,
		},
		{
			name:       "Failure_Empty_Salt",
			email:      "user@example.com",
			serverHash: []byte("super-secret-hash"),
			serverSalt: nil,
			expectedErr: ErrEmptySalt,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, err := NewUser(tt.email, tt.serverHash, tt.serverSalt)

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
				
				if !bytes.Equal(user.ServerHash, tt.serverHash) {
					t.Errorf("expected serverHash %x, got %x", tt.serverHash, user.ServerHash)
				}
				if !bytes.Equal(user.ServerSalt, tt.serverSalt) {
					t.Errorf("expected serverSalt %x, got %x", tt.serverSalt, user.ServerSalt)
				}
			}
		})
	}
}