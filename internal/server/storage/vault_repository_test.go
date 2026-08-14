package storage_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/LeonardoBellan/bassword/internal/server/domain"
	"github.com/LeonardoBellan/bassword/internal/server/storage"
	"github.com/google/uuid"
)

// createExampleCredentials mock credentials
func createExampleCredentials(t *testing.T) (*domain.Credentials, error) {
	t.Helper()

	userID := uuid.New()
	serviceIndex := []byte("example_service_index")
	serviceEncrypted := []byte("example_service_encrypted")
	payloadEncrypted := []byte("encrypted_secred")
	return domain.NewCredentials(userID, serviceIndex, serviceEncrypted, payloadEncrypted)
}

// SetupTestVaultRepository initializes a repository
func setupTestVaultRepository(ctx context.Context, t *testing.T) *storage.SQLiteVaultRepository {
	t.Helper()

	conn,_ := setupInitializedTestDB(ctx,t)
	repository := storage.NewSQLiteVaultRepository(conn)

	return repository
}

func TestVaultRepository_Save(t *testing.T) {
	ctx := context.Background()
	repo := setupTestVaultRepository(ctx, t)

	t.Run("Success_Save", func(t *testing.T) {
		newCredentials, err := createExampleCredentials(t)
		if err != nil { t.Fatalf("Error creating example credentials: %v", err) }

		err = repo.Save(ctx, newCredentials)
		if err != nil {
			t.Fatalf("Error adding credentials: %v", err)
		}

		if newCredentials.CreatedAt.IsZero() {
			t.Errorf("Expected CreatedAt population, is zero")
		}
	})
}

func TestVaultRepository_GetByIdAndUser(t *testing.T) {
	ctx := context.Background()

	// Setup
	repo := setupTestVaultRepository(ctx, t)
	newCredential, err := createExampleCredentials(t)
	if err != nil { t.Fatalf("Error creating example credentials: %v", err) }

	if err := repo.Save(ctx, newCredential); err != nil {
		t.Fatalf("Error saving credentials: %v", err)
	}

	tests := []struct {
		name			string
		id				uuid.UUID
		userID			uuid.UUID
		expectedError	error
	}{
		{
			name: "Success_GetByIdAndUser",
			id: newCredential.ID,
			userID: newCredential.UserID,
			expectedError: nil,
		},{
			name: "Failure_ID_Inexistent",
			id: uuid.New(),
			userID: newCredential.UserID,
			expectedError: domain.ErrNotFound,
		},{
			name: "Failure_UserID_Inexistent",
			id: newCredential.ID,
			userID: uuid.New(),
			expectedError: domain.ErrNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			retrieved, err := repo.GetByIdAndUser(ctx, tt.id, tt.userID)

			if !errors.Is(err, tt.expectedError){
				t.Fatalf("Expected error '%v', got '%v'", tt.expectedError, err)
			}

			if err == nil {

				// Validate fields
				if retrieved == nil {
					t.Errorf("Retrieved credentials are nil")
				}
				if retrieved.ID != newCredential.ID {
					t.Errorf("ID mismatch: expected %s, got %s", newCredential.ID, retrieved.ID)
				}
				if !bytes.Equal(retrieved.ServiceIndex, newCredential.ServiceIndex) {
					t.Errorf("ServiceIndex mismatch")
				}
				if !bytes.Equal(retrieved.PayloadEncrypted, newCredential.PayloadEncrypted) {
					t.Errorf("PayloadEncrypted mismatch")
				}
				if !bytes.Equal(retrieved.PayloadEncrypted, newCredential.PayloadEncrypted) {
					t.Errorf("PayloadEncrypted mismatch")
				}
				if retrieved.CreatedAt != newCredential.CreatedAt {
					t.Errorf("CreatedAt mismatch")
				}
			}
		})
	}
}

func TestVaultRepository_GetByIdAndService(t *testing.T) {
	ctx := context.Background()

	// Setup
	repo := setupTestVaultRepository(ctx, t)
	newCredential, err := createExampleCredentials(t)
	if err != nil { t.Fatalf("Error creating example credentials: %v", err) }

	if err := repo.Save(ctx, newCredential); err != nil {
		t.Fatalf("Error saving credentials: %v", err)
	}

	tests := []struct {
		name			string
		serviceIndex		[]byte
		userID			uuid.UUID
		expectedError	error
	}{
		{
			name: "Success_GetByIdAndService",
			serviceIndex: newCredential.ServiceIndex,
			userID: newCredential.UserID,
			expectedError: nil,
		},{
			name: "Failure_Service_Inexistent",
			serviceIndex: []byte("service_wrong"),
			userID: newCredential.UserID,
			expectedError: domain.ErrNotFound,
		},{
			name: "Failure_UserID_Inexistent",
			serviceIndex: newCredential.ServiceIndex,
			userID: uuid.New(),
			expectedError: domain.ErrNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			retrieved, err := repo.GetByServiceAndUser(ctx, tt.serviceIndex, tt.userID)

			if !errors.Is(err, tt.expectedError){
				t.Fatalf("Expected error '%v', got '%v'", tt.expectedError, err)
			}

			if err == nil {

				// Validate fields
				if retrieved == nil {
					t.Errorf("Retrieved credentials are nil")
				}
				if retrieved.ID != newCredential.ID {
					t.Errorf("ID mismatch: expected %s, got %s", newCredential.ID, retrieved.ID)
				}
				if !bytes.Equal(retrieved.ServiceIndex, newCredential.ServiceIndex) {
					t.Errorf("ServiceIndex mismatch")
				}
				if !bytes.Equal(retrieved.ServiceEncrypted, newCredential.ServiceEncrypted) {
					t.Errorf("ServiceEncrypted mismatch")
				}
				if !bytes.Equal(retrieved.PayloadEncrypted, newCredential.PayloadEncrypted) {
					t.Errorf("PayloadEncrypted mismatch")
				}
				if retrieved.CreatedAt != newCredential.CreatedAt {
					t.Errorf("CreatedAt mismatch")
				}
			}
		})
	}
}
