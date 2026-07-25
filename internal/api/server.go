package api

import (
	"context"

	"github.com/LeonardoBellan/bassword/internal/api/handlers"
	"github.com/LeonardoBellan/bassword/internal/crypto"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func SetupRouter(ctx context.Context, tm *crypto.TokenManager, authHandler *handlers.AuthHandler, vaultHandler *handlers.VaultHandler) *chi.Mux {
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// API v1
	r.Route("/api/v1", func(r chi.Router) {

		// Public
		r.Post("/register", authHandler.HandleRegister)		// POST /api/v1/register
		r.Post("/login", authHandler.HandleLogin)			// POST /api/v1/login

		// Protected
		r.Route("/credentials", func(r chi.Router) {
			r.Use(AuthMiddleware(tm))

			r.Post("/", vaultHandler.HandleCreate)       			// POST /api/v1/credentials
			//r.Get("/", vaultHandler.HandleList)          			// GET /api/v1/credentials
			r.Get("/{service}", vaultHandler.HandleGetByService)   	// GET /api/v1/credentials/{service}
			//r.Delete("/{id}", vaultHandler.HandleDelete) 			// DELETE /api/v1/credentials/{id}
		})
	})

	return r
}