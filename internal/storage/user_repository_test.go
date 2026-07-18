package storage

import (
	"bytes"
	"context"
	"testing"

	"github.com/LeonardoBellan/bassword/internal/models"
)

// createExampleUser mock user
func createExampleUser(t *testing.T) *models.User {
	t.Helper()

	example := &models.User{
		Server_Hash: []byte("hash_example1234"),
		Server_Salt: []byte("salt_example1234"),
	}

	return example
}

// SetupTestUserRepository initializes a repository
func setupTestUserRepository(ctx context.Context, t *testing.T) *SQLiteUserRepository {
	t.Helper()

	// 
	conn, _, _ := setupInitializedTestDB(ctx, t)
	repository := NewSQLiteUserRepository(conn)

	return repository
}

func TestUserRepository_IntegrationFlow(t *testing.T) {
	ctx := context.Background()

	// Setup
	repo := setupTestUserRepository(ctx, t)
	newUser := createExampleUser(t)

	t.Run("Save_Success", func(t *testing.T) {
		// Add user
		err := repo.Save(ctx, newUser)
		
		if err != nil {
			t.Fatalf("Error adding user: %v", err)
		}

		if newUser.ID == 0 {
			t.Errorf("Expected ID population, is zero")
		}
	})

	t.Run("Get_Success", func(t *testing.T) {
		// Get user by ID
		retrieved, err := repo.Get(ctx, newUser.ID)
		
		if err != nil {
			t.Fatalf("Error getting user: %v", err)
		}
		if retrieved == nil {
			t.Fatalf("User Not Found")
		}

		// Verify matching data with example
		if retrieved.ID != newUser.ID {
			t.Errorf("ID mismatch: expected %d, got %d", newUser.ID, retrieved.ID)
		}
		if retrieved.Email != newUser.Email {
			t.Errorf("Email mismatch: expected %v, got %v", newUser.Email, retrieved.Email)
		}
		if !bytes.Equal(retrieved.Server_Hash, newUser.Server_Hash) {
			t.Errorf("Corrupted encrypted data or not correct. Expected %v, got %v", newUser.Server_Hash, retrieved.Server_Hash)
		}
		if !bytes.Equal(retrieved.Server_Salt, newUser.Server_Salt) {
			t.Errorf("Corrupted encrypted data or not correct. Expected %v, got %v", newUser.Server_Salt, retrieved.Server_Salt)
		}
	})

	t.Run("Get_Failure_ID_Not_Existing", func(t *testing.T) {
		// Expected failure
		idInexistent := 99999
		user, err := repo.Get(ctx, idInexistent)
		
		if err != nil {
        	t.Fatalf("Expected no error, got: %v", err)
		}
    	if user != nil {
        	t.Errorf("Expected user to be nil, got: %+v", user)
    	}
	})
}