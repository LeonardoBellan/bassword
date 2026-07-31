package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"regexp"

	"github.com/LeonardoBellan/bassword/internal/server/domain"
)

// Authentication
type authRequest struct {
	Email   string 	`json:"email"`
	AuthHash string `json:"auth_hash"`
}

// DTO
func (req *authRequest) isValid() error {
	// Validate input
	var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(req.Email) {
		return domain.ErrInvalidEmail
	}
	if len(req.AuthHash) == 0 {
		return domain.ErrMissingSecretHash
	}

	return nil
}

type loginResponse struct {
	Status string    `json:"status"`
	Data   loginData `json:"data"`
}

type loginData struct {
	Token string    `json:"token"`
}

// Dependencies
type AuthService interface {
	Register(ctx context.Context, email string, authHash []byte) error
	Authenticate(ctx context.Context, email string, authHash []byte) (string, error)
}

type AuthHandler struct {
	service AuthService
}

func NewAuthHandler(s AuthService) *AuthHandler {
	return &AuthHandler{ service: s }
}

// Handlers
func (h *AuthHandler) HandleRegister(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 1048576)

	// Decode
	var req authRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondWithError(w, http.StatusBadRequest, "Invalid JSON format")
		return 
	}

	// Request validity
	if err := req.isValid(); err != nil {
		// TODO - Map internal errors
		RespondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.service.Register(ctx, req.Email, []byte(req.AuthHash)); err != nil {		
		if errors.Is(err, domain.ErrUserExists){
			RespondWithError(w, http.StatusConflict, "User already registered")
			return
		}
		
		log.Printf("Unexpected error: %v", err)
		RespondWithError(w, http.StatusInternalServerError, "Unexpected error")
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
	var req authRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondWithError(w, http.StatusBadRequest, "Invalid JSON format")
		return 
	}

	// Request validity
	if err := req.isValid(); err != nil {
		if errors.Is(err, domain.ErrInvalidEmail) {
			RespondWithError(w, http.StatusBadRequest, "Invalid email format")
			return
		}
		if errors.Is(err, domain.ErrMissingSecretHash){
			RespondWithError(w, http.StatusBadRequest, "Field 'auth_hash' is required")
			return
		}

		log.Printf("Unexpected error: %v", err)
		RespondWithError(w, http.StatusInternalServerError, "Unexpected error")
		return
	}

	token,err :=  h.service.Authenticate(ctx, req.Email, []byte(req.AuthHash))
	if err != nil {

		// Authorization errors
		if errors.Is(err, domain.ErrUserNotFound) || errors.Is(err, domain.ErrInvalidSecret) {
			RespondWithError(w, http.StatusUnauthorized, "Authentication failed. Invalid credentials provided.")
			return
		}

		log.Printf("Unexpected error; %v", err)
		RespondWithError(w, http.StatusInternalServerError, "Unexpected error")

		return
	}

	// Response
	res := &loginResponse{
		Status: "success",
		Data: loginData{
			Token: token,
		},
	}

	RespondWithJSON(w, http.StatusOK, res)
}