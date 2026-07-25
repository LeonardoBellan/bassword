package handlers

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	"github.com/LeonardoBellan/bassword/internal/domain"
	"github.com/go-chi/chi/v5"
)

// DTO
type credentialsPayload struct {
	ServiceName   string `json:"service_name"`
    EncryptedData string `json:"encrypted_data"`
}


// Dependencies
type VaultService interface {
	Save(ctx context.Context, userID int, serviceName string, encryptedData []byte) error
	GetForService(ctx context.Context, serviceName string, userID int) (*domain.Credentials, error)
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

	userID := r.Context().Value("user_id").(int)
	
	// Decode body
	var req credentialsPayload
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondWithError(w, http.StatusBadRequest, "Invalid JSON format")
		return 
	}

	// Validazione input
	if req.ServiceName == "" {
		RespondWithError(w, http.StatusBadRequest, "Field 'service_name' is required")
		return
	}
	if len(req.EncryptedData) == 0 {
		RespondWithError(w, http.StatusBadRequest, "Field 'encrypted_data' is required")
		return
	}

	if err := h.service.Save(ctx, userID, req.ServiceName, []byte(req.EncryptedData)); err != nil {
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

	userID := r.Context().Value("user_id").(int)
	serviceName := chi.URLParam(r, "service")

	if serviceName == "" {
		RespondWithError(w, http.StatusBadRequest, "Field 'service_name' is required")
		return
	}

	credentials,err := h.service.GetForService(ctx, serviceName, userID);
	if err != nil {
		// TODO - Map internal errors
		log.Printf("Unexpected error; %v", err)
		RespondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Response
	res := credentialsPayload {
		ServiceName: credentials.ServiceName,
		EncryptedData: string(credentials.EncryptedData),
	}
	RespondWithJSON(w, http.StatusOK, res)
}