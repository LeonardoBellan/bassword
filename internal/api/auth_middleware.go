package api

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/LeonardoBellan/bassword/internal/api/handlers"
	"github.com/LeonardoBellan/bassword/internal/crypto"
	"github.com/golang-jwt/jwt/v5"
)

func AuthMiddleware(tm *crypto.TokenManager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler{
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			// Get token
			prefix := "Bearer "
			authHeader := r.Header.Get("Authorization")
			reqToken := strings.TrimPrefix(authHeader, prefix)

			// Validate token and add userID to context
			userID, err := tm.ValidateToken(reqToken)
			if err != nil {
				if errors.Is(err, jwt.ErrTokenExpired) {
					handlers.RespondWithError(w, http.StatusUnauthorized, "Expired token")
					return
				}

				handlers.RespondWithError(w, http.StatusUnauthorized, "Invalid token")
				return
			}	

			log.Printf("User ID: %v", userID)
			ctx := context.WithValue(r.Context(), "user_id", userID)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}