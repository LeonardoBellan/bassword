package api

import (
	"context"
	"log"
	"net/http"
	"strings"

	"github.com/LeonardoBellan/bassword/internal/crypto"
	"github.com/LeonardoBellan/bassword/internal/handlers"
)

func AuthMiddleware(tm *crypto.TokenManager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler{
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			// Get token
			prefix := "Bearer "
			authHeader := r.Header.Get("Authorization")
			reqToken := strings.TrimPrefix(authHeader, prefix)

			// Validate token and add userID to context
			userID,err := tm.ValidateToken(reqToken)
			if err != nil {
				handlers.RespondWithError(w, http.StatusBadRequest, "Invalid token")
				return
			}	

			log.Printf("User ID: %v", userID)
			ctx := context.WithValue(r.Context(), "user_id", userID)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}