package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/golang-jwt/jwt/v5"
)

var ErrInvalidToken = errors.New("invalid token format")

// Creates and validates JWT
type TokenManager struct {
	jwtKey []byte
	ttl time.Duration
}

func NewTokenManager(jwtKey string, expDuration time.Duration) (*TokenManager, error) {

	if jwtKey == "" {
		return nil, fmt.Errorf("Empty jwt key")
	}

	if expDuration <= 0 {
		return nil, fmt.Errorf("expDuration must be greater than 0")
	}

	return &TokenManager{ 
		jwtKey: []byte(jwtKey),
		ttl: expDuration,
	}, nil
}

// GenerateToken generates a JWT using a secret key with userID custom claim and duration ttl
// Returns the token string
func (tm *TokenManager) GenerateToken(userID uuid.UUID) (string, error) {
	// Prepare JWT Claims

	claims := jwt.RegisteredClaims{
		Issuer:    "bassword",
		Subject:   userID.String(),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(tm.ttl)),
	}

	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString(tm.jwtKey)
}

// ValidateToken validates a token string of a user
// Returns the user ID in the subject claim
func (tm *TokenManager) ValidateToken(tokenString string) (uuid.UUID, error) {
	claims := &jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("%w: unsupported signing method (%v)", ErrInvalidToken, token.Header["alg"])
		}
		return tm.jwtKey, nil			
	})
	if err != nil || !token.Valid {
		if errors.Is(err, ErrInvalidToken) {
			return uuid.Nil, err
		}

		return uuid.Nil, fmt.Errorf("%w: %v", ErrInvalidToken, err) 
	}

	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return uuid.Nil, fmt.Errorf("%w: malformed subject UUID: %v", ErrInvalidToken, err)
	}
	return userID, nil
}
