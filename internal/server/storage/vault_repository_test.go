package storage

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/LeonardoBellan/bassword/internal/server/domain"
)

// createExampleCredentials mock credentials
func createExampleCredentials(t *testing.T) (*domain.Credentials, error) {
	t.Helper()

	userID := "123e4567-e89b-12d3-a456-426614174000"
	serviceName := "service_example"
	encryptedData := []byte("encrypted_secred")
	return domain.NewCredentials(userID, serviceName, encryptedData)
}

// SetupTestUserRepository initializes a repository
func setupTestVaultRepository(ctx context.Context, t *testing.T) *SQLiteVaultRepository {
	t.Helper()

	conn,_ := setupInitializedTestDB(ctx,t)
	repository := NewSQLiteVaultRepository(conn)

	return repository
}

func TestVaultRepository_IntegrationFlow(t *testing.T) {
	ctx := context.Background()

	// Setup
	repo := setupTestVaultRepository(ctx, t)
	newCredential, err := createExampleCredentials(t)
	if err != nil { t.Fatalf("Error creating example credentials: %v", err) }

	t.Run("Save_Success", func(t *testing.T) {
		err := repo.Save(ctx, newCredential)
		
		if err != nil {
			t.Fatalf("Error adding credentials: %v", err)
		}

		if newCredential.CreatedAt.IsZero() {
			t.Errorf("Expected CreatedAt population, is zero")
		}
	})

	t.Run("GetByIdAndUser_Success", func(t *testing.T) {
		retrieved, err := repo.GetByIdAndUser(ctx, newCredential.ID, newCredential.UserID)
		
		if err != nil {
			t.Fatalf("Error getting credentials: %v", err)
		}

		if retrieved == nil {
			t.Fatalf("User Not Found")
		}

		if retrieved.ServiceName != newCredential.ServiceName {
			t.Errorf("ServiceName mismatch: expected %s, got %s", newCredential.ServiceName, retrieved.ServiceName)
		}
	})

	t.Run("GetByIdAndUser_Failure_ID_Not_Existing", func(t *testing.T) {
		idInexistent := "00000000-0000-0000-0000-000000000000"
		_, err := repo.GetByIdAndUser(ctx, idInexistent, newCredential.UserID)
		
		if !errors.Is(err, domain.ErrNotFound) {
			t.Errorf("Expected %v, got %v",domain.ErrNotFound,err)
		}
	})

	t.Run("GetByIdAndUser_Failure_userID_Not_Existing", func(t *testing.T) {
		idInexistent := "00000000-0000-0000-0000-000000000000"
		_, err := repo.GetByIdAndUser(ctx, newCredential.ID, idInexistent)
		
		if !errors.Is(err, domain.ErrNotFound) {
			t.Errorf("Expected %v, got %v",domain.ErrNotFound,err)
		}
	})

	t.Run("GetByUserAndService_Success", func(t *testing.T) {
		retrieved, err := repo.GetByServiceAndUser(ctx, newCredential.ServiceName, newCredential.UserID)
		
		// Verify matching data with example
		if err != nil {
			t.Fatalf("Error getting credentials: %v", err)
		}
		if retrieved == nil {
			t.Fatalf("User Not Found")
		}

		if retrieved.ID != newCredential.ID {
			t.Errorf("ID mismatch: expected %s, got %s", newCredential.ID, retrieved.ID)
		}

		if !bytes.Equal(retrieved.EncryptedData, newCredential.EncryptedData) {
			t.Errorf("Corrupted encrypted data or not correct. Expected %v, got %v", newCredential.EncryptedData, retrieved.EncryptedData)
		}
	})

	t.Run("GetByUserAndService_Failure_Service_Not_Existing", func(t *testing.T) {
		serviceInexistent := "gabagool"
		_, err := repo.GetByServiceAndUser(ctx, serviceInexistent, newCredential.UserID)
		
		// Verify matching data with example
		if !errors.Is(err, domain.ErrNotFound) {
			t.Errorf("Expected %v, got %v",domain.ErrNotFound,err)
		}
	})

	t.Run("GetByUserAndService_Failure_userID_Not_Existing", func(t *testing.T) {
		idInexistent := "00000000-0000-0000-0000-000000000000"
		_, err := repo.GetByServiceAndUser(ctx, newCredential.ServiceName, idInexistent)
		
		// Verify matching data with example
		if !errors.Is(err, domain.ErrNotFound) {
			t.Errorf("Expected %v, got %v",domain.ErrNotFound,err)
		}
	})
}