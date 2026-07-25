package handlers

import (
	"encoding/json"
	"net/http"
)

type APIResponse struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

func RespondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Set("Content-Type","application/json")
	w.WriteHeader(code)

	if payload != nil {
		_ = json.NewEncoder(w).Encode(payload)
	}
}

func RespondWithError(w http.ResponseWriter, code int, message string) {
	RespondWithJSON(w, code, map[string]string{"error": message})
}