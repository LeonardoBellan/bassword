package handlers

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
)

type AuthService interface {
	Register(ctx context.Context, email string, authHash []byte) error
	Authenticate(ctx context.Context, email string, authHash []byte) (string, error)
}

type AuthHandler struct {
	service AuthService
}

func NewAuthHandler(s AuthService) *AuthHandler {
	return &AuthHandler{ service: s}
}


func (h *AuthHandler) HandleRegister(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 1048576)

	// Decode
	var req AuthRequest
	log.Printf("Req: %v, %v", req.Email, req.AuthHash)

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondWithError(w, http.StatusBadRequest, "Invalid JSON format")
		return 
	}

	// Request validity
	if err := req.IsValid(); err != nil {
		RespondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.service.Register(ctx, req.Email, []byte(req.AuthHash)); err != nil {
		RespondWithError(w, http.StatusInternalServerError, err.Error())
		// TODO - Map internal errors
		return
	}

	// Response
	RespondWithJSON(w, http.StatusCreated, map[string]string{
		"status": "success",
		"message": "User created successfully",
	})
}

func (h *AuthHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 1048576)

	// Decode
	var req AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondWithError(w, http.StatusBadRequest, "Invalid JSON format")
		return 
	}

	// Request validity
	if err := req.IsValid(); err != nil {
		RespondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	token,err :=  h.service.Authenticate(ctx, req.Email, []byte(req.AuthHash))
	if err != nil {
		RespondWithError(w, http.StatusInternalServerError, "Unexpected error")
		// TODO - Map internal errors
		return
	}

	// Response
	res := &LoginResponse{
		Status: "success",
		Data: LoginData{
			Token: token,
		},
	}

	RespondWithJSON(w, http.StatusOK, res)
}