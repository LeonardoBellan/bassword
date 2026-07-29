package api

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/LeonardoBellan/bassword/internal/server/api/handlers"
	"github.com/LeonardoBellan/bassword/internal/shared/crypto"
	"github.com/golang-jwt/jwt/v5"
)

// AuthMiddleware verifies the provided token and saves in the context the user ID
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

			ctx := context.WithValue(r.Context(), "user_id", userID)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}