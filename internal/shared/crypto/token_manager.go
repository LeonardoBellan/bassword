package crypto

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Creates and validates JWT
type TokenManager struct {
	jwtKey []byte
}

func NewTokenManager(jwtKey string) *TokenManager {
	return &TokenManager{ jwtKey: []byte(jwtKey) }
}

// GenerateToken generates a JWT using a secret key with userID custom claim and duration ttl
func (tm *TokenManager) GenerateToken(userID int, ttl time.Duration) (string, error) {
	// Prepare JWT Claims

	claims := jwt.RegisteredClaims{
		Issuer:    "bassword",
		Subject:   strconv.Itoa(userID),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
	}

	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString(tm.jwtKey)
}

func (tm *TokenManager) ValidateToken(tokenString string) (int, error) {
	claims := &jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("%w: unsupported signing method (%v)", ErrInvalidToken, token.Header["alg"])
		}
		return tm.jwtKey, nil			
	})
	if err != nil || !token.Valid {
		if errors.Is(err, ErrInvalidToken) {
			return 0, err
		}

		return 0, fmt.Errorf("%w: %v", ErrInvalidToken, err) 
	}

	return strconv.Atoi(claims.Subject)
}