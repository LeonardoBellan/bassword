package handlers

import (
	"context"
	"encoding/json"
	"encoding/base64"
	"errors"
	"log"
	"net/http"

	"github.com/LeonardoBellan/bassword/internal/server/domain"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// DTO
type credentialsPayload struct {
	ServiceNameIndex   []byte `json:"service_name_index"`
  EncryptedData []byte `json:"encrypted_data"`
}

// Dependencies
type VaultService interface {
	Save(ctx context.Context, userID uuid.UUID, serviceNameIndex []byte, encryptedData []byte) error
	GetForService(ctx context.Context, serviceNameIndex []byte, userID uuid.UUID) (*domain.Credentials, error)
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

	// Validazione input
	if len(req.ServiceNameIndex) == 0 {
		RespondWithError(w, http.StatusBadRequest, "Field 'service_name' is required")
		return
	}
	if len(req.EncryptedData) == 0 {
		RespondWithError(w, http.StatusBadRequest, "Field 'encrypted_data' is required")
		return
	}

	if err := h.service.Save(ctx, userID, req.ServiceNameIndex, req.EncryptedData); err != nil {
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

	// Retrieve and decode serviceNameIndex from request
	serviceParam := chi.URLParam(r, "service")
	serviceNameIndex, err := base64.RawURLEncoding.DecodeString(serviceParam)
	if err != nil {
		RespondWithError(w, http.StatusBadRequest, "Invalid Service parameter")
		return
	}

	// Retrieve user ID from context
	envVal := r.Context().Value("user_id")
	userID, ok := envVal.(uuid.UUID)
	if !ok {
		RespondWithError(w, http.StatusUnauthorized, "Unauthorized")
	}

	if len(serviceNameIndex) == 0 {
		RespondWithError(w, http.StatusBadRequest, "Field 'service_name' is required")
		return
	}

	credentials,err := h.service.GetForService(ctx, serviceNameIndex, userID);
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
		ServiceNameIndex: credentials.ServiceNameIndex,
		EncryptedData: credentials.EncryptedData,
	}
	RespondWithJSON(w, http.StatusOK, res)
}
