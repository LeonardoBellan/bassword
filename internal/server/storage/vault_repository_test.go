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
	serviceNameIndex := []byte("service_example")
	encryptedData := []byte("encrypted_secred")
	return domain.NewCredentials(userID, serviceNameIndex, encryptedData)
}

// SetupTestVaultRepository initializes a repository
func setupTestVaultRepository(ctx context.Context, t *testing.T) *storage.SQLiteVaultRepository {
	t.Helper()

	conn,_ := setupInitializedTestDB(ctx,t)
	repository := storage.NewSQLiteVaultRepository(conn)

	return repository
}

func TestSave(t *testing.T) {
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

func TestGetByIdAndUser(t *testing.T) {
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
				if !bytes.Equal(retrieved.ServiceNameIndex, newCredential.ServiceNameIndex) {
					t.Errorf("ServiceNameIndex mismatch")
				}
				if !bytes.Equal(retrieved.EncryptedData, newCredential.EncryptedData) {
					t.Errorf("EncryptedData mismatch")
				}
				if !bytes.Equal(retrieved.EncryptedData, newCredential.EncryptedData) {
					t.Errorf("EncryptedData mismatch")
				}
				if retrieved.CreatedAt != newCredential.CreatedAt {
					t.Errorf("CreatedAt mismatch")
				}
			}
		})
	}
}

func TestGetByIdAndService(t *testing.T) {
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
		serviceNameIndex		[]byte
		userID			uuid.UUID
		expectedError	error
	}{
		{
			name: "Success_GetByIdAndService",
			serviceNameIndex: newCredential.ServiceNameIndex,
			userID: newCredential.UserID,
			expectedError: nil,
		},{
			name: "Failure_Service_Inexistent",
			serviceNameIndex: []byte("service_wrong"),
			userID: newCredential.UserID,
			expectedError: domain.ErrNotFound,
		},{
			name: "Failure_UserID_Inexistent",
			serviceNameIndex: newCredential.ServiceNameIndex,
			userID: uuid.New(),
			expectedError: domain.ErrNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			retrieved, err := repo.GetByServiceAndUser(ctx, tt.serviceNameIndex, tt.userID)

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
				if !bytes.Equal(retrieved.ServiceNameIndex, tt.serviceNameIndex) {
					t.Errorf("ServiceNameIndex mismatch")
				}
				if !bytes.Equal(retrieved.EncryptedData, newCredential.EncryptedData) {
					t.Errorf("EncryptedData mismatch")
				}
				if retrieved.CreatedAt != newCredential.CreatedAt {
					t.Errorf("CreatedAt mismatch")
				}
			}
		})
	}
}
