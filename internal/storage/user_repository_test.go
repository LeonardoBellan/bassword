package storage

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/LeonardoBellan/bassword/internal/domain"
)

// createExampleUser mock user
func createExampleUser(t *testing.T) (*domain.User, error) {
	t.Helper()

	return domain.NewUser("username@example.com", []byte("hash_example1234"), []byte("salt_example1234"))
}

// SetupTestUserRepository initializes a repository
func setupTestUserRepository(ctx context.Context, t *testing.T) *SQLiteUserRepository {
	t.Helper()

	// Inizialize repository
	conn, _ := setupInitializedTestDB(ctx, t)
	repository := NewSQLiteUserRepository(conn)

	return repository
}

func TestUserRepository_IntegrationFlow(t *testing.T) {
	ctx := context.Background()

	// Setup
	repo := setupTestUserRepository(ctx, t)
	newUser, err  := createExampleUser(t)
	if err != nil { t.Fatalf("Error creating example user: %v", err) }

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

	/**** Get ****/
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
		if !bytes.Equal(retrieved.ServerHash, newUser.ServerHash) {
			t.Errorf("Corrupted encrypted data or not correct. Expected %v, got %v", newUser.ServerHash, retrieved.ServerHash)
		}
		if !bytes.Equal(retrieved.ServerSalt, newUser.ServerSalt) {
			t.Errorf("Corrupted encrypted data or not correct. Expected %v, got %v", newUser.ServerSalt, retrieved.ServerSalt)
		}
	})

	t.Run("Get_Failure_ID_Not_Existing", func(t *testing.T) {
		// Expected failure
		idInexistent := 99999
		_, err := repo.Get(ctx, idInexistent)
		
		if !errors.Is(err, domain.ErrNotFound) {
			t.Errorf("Expected %v, got %v",domain.ErrNotFound,err)
		}
	})

	/**** Get by email ****/
	t.Run("GetByEmail_Success", func(t *testing.T) {
		// Get user by email
		retrieved, err := repo.GetByEmail(ctx, newUser.Email)
		
		if err != nil {
			t.Fatalf("Error getting user: %v", err)
		}

		// Verify matching data with example
		if retrieved.ID != newUser.ID {
			t.Errorf("ID mismatch: expected %d, got %d", newUser.ID, retrieved.ID)
		}
		if retrieved.Email != newUser.Email {
			t.Errorf("Email mismatch: expected %v, got %v", newUser.Email, retrieved.Email)
		}
		if !bytes.Equal(retrieved.ServerHash, newUser.ServerHash) {
			t.Errorf("Corrupted encrypted data or not correct. Expected %v, got %v", newUser.ServerHash, retrieved.ServerHash)
		}
		if !bytes.Equal(retrieved.ServerSalt, newUser.ServerSalt) {
			t.Errorf("Corrupted encrypted data or not correct. Expected %v, got %v", newUser.ServerSalt, retrieved.ServerSalt)
		}
	})

	t.Run("GetByEmail_Failure_Email_Not_Existing", func(t *testing.T) {
		// Expected failure
		emailInexistent := "wrongusername@example.com"
		_, err := repo.GetByEmail(ctx, emailInexistent)
		
		if !errors.Is(err, domain.ErrNotFound) {
			t.Errorf("Expected %v, got %v",domain.ErrNotFound,err)
		}
	})
}