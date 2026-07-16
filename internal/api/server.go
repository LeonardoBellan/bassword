package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func SetupRouter(credHandler *handlers.CredentialHandler) *chi.Mux {
	r := chi.NewRouter()

	// 1. Middleware Globali (applicati a TUTTE le richieste)
	r.Use(middleware.RequestID) // Genera un ID per ogni richiesta (ottimo per il debug)
	r.Use(middleware.Logger)    // Stampa log puliti sul terminale
	r.Use(middleware.Recoverer) // Se l'app va in panico, non fa crashare il server

	// 2. Gruppo API v1
	r.Route("/api/v1", func(r chi.Router) {

		// Rotte pubbliche (es. Healthcheck)
		r.Get("/ping", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("pong"))
		})

		// Gruppo Rotte Protette (Credentials)
		r.Route("/credentials", func(r chi.Router) {
			// r.Use(mioMiddlewareDiAuth)

			r.Post("/", credHandler.HandleCreate)       // POST /api/v1/credentials
			r.Get("/", credHandler.HandleList)          // GET /api/v1/credentials
			r.Get("/{id}", credHandler.HandleGetByID)   // GET /api/v1/credentials/{id}
			r.Delete("/{id}", credHandler.HandleDelete) // DELETE /api/v1/credentials/{id}
		})
	})

	return r
}