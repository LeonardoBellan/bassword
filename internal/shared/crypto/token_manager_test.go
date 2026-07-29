package crypto

import (
	"testing"
	"time"
)

func TestTokenFlow(t *testing.T) {
	secretKey := "correct-secret-jwt-key"
	wrongKey := "incorrect-secret-jwt-key"
	userID := 1

	t.Run("Success_Valid_Token", func(t *testing.T){
		tm := NewTokenManager(secretKey, 15*time.Minute)
		
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
			name: "Failure_Tampered_Token",
			setupToken: func() (string, *TokenManager) {
				tm := NewTokenManager(secretKey, 15*time.Minute)

				tokenStr, _ := tm.GenerateToken(userID) 
				tamperedStr := tokenStr[:len(tokenStr)-1] + "X"
				return tamperedStr, tm
			},
			expectedErr: true,
		},{
			name: "Failure_Expired_Token",
			setupToken: func() (string, *TokenManager) {
				tm := NewTokenManager(secretKey, -1*time.Minute)

				tokenStr, _ := tm.GenerateToken(userID)
				return tokenStr, tm
			},
			expectedErr: true,
		},{
			name: "Failure_Wrong_signing_Key",
			setupToken: func() (string, *TokenManager) {
				// Token manager A generates jwt
				tmA := NewTokenManager(secretKey, 15*time.Minute)
				tokenStr, _ := tmA.GenerateToken(userID)
			
				// Token manager B is used to validate with wrong key
				tmB := NewTokenManager(wrongKey, 15*time.Minute)
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