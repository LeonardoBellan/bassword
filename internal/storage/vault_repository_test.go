package storage

import (
	"bytes"
	"context"
	"testing"

	"github.com/LeonardoBellan/bassword/internal/models"
)

// createExampleCredentials mock credentials
func createExampleCredentials(t *testing.T) *models.Credentials {
	t.Helper()

	example := &models.Credentials{
		UserID: 1,
		ServiceName: "service_example",
		EncryptedData: []byte("crypted_secret"),
	}

	return example
}

// SetupTestUserRepository initializes a repository
func setupTestVaultRepository(ctx context.Context, t *testing.T) *SQLiteVaultRepository {
	t.Helper()

	conn,_,_ := setupInitializedTestDB(ctx,t)
	repository := NewSQLiteVaultRepository(conn)

	return repository
}


func TestVaultRepository_IntegrationFlow(t *testing.T) {
	ctx := context.Background()

	// Setup
	repo := setupTestVaultRepository(ctx, t)
	newCredential := createExampleCredentials(t)

	t.Run("Save_Success", func(t *testing.T) {
		err := repo.Save(ctx, newCredential)
		
		if err != nil {
			t.Fatalf("Error adding credentials: %v", err)
		}

		if newCredential.ID == 0 {
			t.Errorf("Expected ID population, is zero")
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
		idInexistent := 99999
		credentials, err := repo.GetByIdAndUser(ctx, idInexistent, newCredential.UserID)
		
		if err != nil {
        	t.Fatalf("Expected no error, got: %v", err)
		}
    	if credentials != nil {
        	t.Errorf("Expected credential to be nil, got: %+v", credentials)
    	}
	})

	t.Run("GetByIdAndUser_Failure_userID_Not_Existing", func(t *testing.T) {
		idInexistent := 99999
		credentials, err := repo.GetByIdAndUser(ctx, newCredential.ID, idInexistent)
		
		if err != nil {
        	t.Fatalf("Expected no error, got: %v", err)
		}
    	if credentials != nil {
        	t.Errorf("Expected credential to be nil, got: %+v", credentials)
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
			t.Errorf("ID mismatch: expected %d, got %d", newCredential.ID, retrieved.ID)
		}

		if !bytes.Equal(retrieved.EncryptedData, newCredential.EncryptedData) {
			t.Errorf("Corrupted encrypted data or not correct. Expected %v, got %v", newCredential.EncryptedData, retrieved.EncryptedData)
		}
	})

	t.Run("GetByUserAndService_Failure_Service_Not_Existing", func(t *testing.T) {
		serviceInexistent := "gabagool"
		credentials, err := repo.GetByServiceAndUser(ctx, serviceInexistent, newCredential.UserID)
		
		// Verify matching data with example
		if err != nil {
        	t.Fatalf("Expected no error, got: %v", err)
		}
    	if credentials != nil {
        	t.Errorf("Expected credential to be nil, got: %+v", credentials)
    	}
	})

	t.Run("GetByUserAndService_Failure_userID_Not_Existing", func(t *testing.T) {
		idInexistent := 99999
		credentials, err := repo.GetByServiceAndUser(ctx, newCredential.ServiceName, idInexistent)
		
		// Verify matching data with example
		if err != nil {
        	t.Fatalf("Expected no error, got: %v", err)
		}
    	if credentials != nil {
        	t.Errorf("Expected credential to be nil, got: %+v", credentials)
    	}
	})

	
}