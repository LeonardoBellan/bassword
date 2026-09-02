package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestTokenFlow(t *testing.T) {
	secretKey := "correct-secret-jwt-key"
	wrongKey := "incorrect-secret-jwt-key"
	userID := uuid.New()

	t.Run("Success_Valid_Token", func(t *testing.T){
		tm, err := NewTokenManager(secretKey, 15*time.Minute)
		if err != nil {
			t.Fatalf("Error in token manager setup: %v", err)
		}
		
		tokenString, err := tm.GenerateToken(userID)
		if err != nil {
			t.Fatalf("Error generating jwt: %v", err)
		}

		parsedID, err := tm.ValidateToken(tokenString)
		if err != nil {
			t.Fatalf("Error validating jwt: %v", err)
		}

		if parsedID != userID {
			t.Errorf("Expected user id %v, got %v", userID, parsedID)
		}
	})

	tests := []struct {
		name		string
		setupToken	func() (string, *TokenManager)
		expectedErr	bool
	}{
		{
			name: "Failure_Token_Tampered",
			setupToken: func() (string, *TokenManager) {
				tm, err := NewTokenManager(secretKey, 15*time.Minute)
				if err != nil {
					t.Fatalf("Error in token manager setup: %v", err)
				}

				tokenStr, err := tm.GenerateToken(userID)
				if err != nil {
					t.Fatalf("Failed to generate token: %v", err)
				}

				tamperedStr := tokenStr[:len(tokenStr)-1] + "X"
				return tamperedStr, tm
			},
			expectedErr: true,
		},{
			name: "Failure_Token_Expired",
			setupToken: func() (string, *TokenManager) {
				tm, err := NewTokenManager(secretKey, 1*time.Millisecond)
				if err != nil {
					t.Fatalf("Error in token manager setup: %v", err)
				}

				tokenStr, err := tm.GenerateToken(userID)
				if err != nil {
					t.Fatalf("Failed to generate token: %v", err)
				}

				time.Sleep(10 * time.Millisecond)

				return tokenStr, tm
			},
			expectedErr: true,
		},{
			name: "Failure_Wrong_Signing_Key",
			setupToken: func() (string, *TokenManager) {
				// Token manager A generates jwt
				tmA, err := NewTokenManager(secretKey, 15*time.Minute)
				if err != nil {
					t.Fatalf("Error in token manager setup: %v", err)
				}
				tokenStr, err := tmA.GenerateToken(userID)
				if err != nil {
					t.Fatalf("Failed to generate token: %v", err)
				}
			
				// Token manager B is used to validate with wrong key
				tmB, err := NewTokenManager(wrongKey, 15*time.Minute)
				if err != nil {
					t.Fatalf("Error in token manager setup: %v", err)
				}
				return tokenStr, tmB
			},
			expectedErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenStr, validationManager := tt.setupToken()
			_, err := validationManager.ValidateToken(tokenStr)
		
			if tt.expectedErr && err == nil {
				t.Error("Expected an error but validation passed successfully")
			}
			if !tt.expectedErr && err != nil {
				t.Errorf("Expected no error but validation failed: %v", err)
			}
		})
	}
}
