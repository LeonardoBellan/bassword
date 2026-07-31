package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/LeonardoBellan/bassword/internal/server/domain"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// DTO
type credentialsPayload struct {
	ServiceName   string `json:"service_name"`
    EncryptedData string `json:"encrypted_data"`
}

// Dependencies
type VaultService interface {
	Save(ctx context.Context, userID uuid.UUID, serviceName string, encryptedData []byte) error
	GetForService(ctx context.Context, serviceName string, userID uuid.UUID) (*domain.Credentials, error)
}

type VaultHandler struct {
	service VaultService
}

func NewVaultHandler(s VaultService) *VaultHandler {
	return &VaultHandler{ service:s }
}

// Handlers
func (h *VaultHandler) HandleCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 1048576)

	// Get user ID from context
	envVal := r.Context().Value("user_id")
	userID, ok := envVal.(uuid.UUID)
	if !ok {
		RespondWithError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	
	// Decode body
	var req credentialsPayload
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondWithError(w, http.StatusBadRequest, "Invalid JSON format")
		return 
	}

	ciphertext, err := base64.URLEncoding.DecodeString(req.EncryptedData)
	if err != nil {
    	RespondWithError(w, http.StatusBadRequest, "Invalid Base64 encoding in encrypted_data")
    	return
	}

	// Validazione input
	if req.ServiceName == "" {
		RespondWithError(w, http.StatusBadRequest, "Field 'service_name' is required")
		return
	}
	if len(ciphertext) == 0 {
		RespondWithError(w, http.StatusBadRequest, "Field 'encrypted_data' is required")
		return
	}

	if err := h.service.Save(ctx, userID, req.ServiceName, ciphertext); err != nil {
		// TODO - Map internal errors
		log.Printf("Unexpected error; %v", err)
		RespondWithError(w, http.StatusInternalServerError, "Unexpected error")
		return
	}

	// Response
	RespondWithJSON(w, http.StatusCreated, map[string]string{
		"status": "success",
		"message": "Vault entry created successfully",
	})
}

func (h *VaultHandler) HandleGetByService(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Retrieve serviceName from request
	serviceName := chi.URLParam(r, "service")

	// Retrieve user ID from context
	envVal := r.Context().Value("user_id")
	userID, ok := envVal.(uuid.UUID)
	if !ok {
		RespondWithError(w, http.StatusUnauthorized, "Unauthorized")
	}

	if serviceName == "" {
		RespondWithError(w, http.StatusBadRequest, "Field 'service_name' is required")
		return
	}

	credentials,err := h.service.GetForService(ctx, serviceName, userID);
	if err != nil {

		if errors.Is(err, domain.ErrCredentialsNotFound) {
			RespondWithError(w, http.StatusNotFound, "Credentials not found")
			return
		}

		log.Printf("Unexpected error: %v", err)
		RespondWithError(w, http.StatusInternalServerError, "Unexpected error")
		return
	}

	// Response
	res := credentialsPayload {
		ServiceName: credentials.ServiceName,
		EncryptedData: base64.URLEncoding.EncodeToString(credentials.EncryptedData),
	}
	RespondWithJSON(w, http.StatusOK, res)
}