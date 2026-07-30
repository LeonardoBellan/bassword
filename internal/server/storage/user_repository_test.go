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

// createExampleUser mock user
func createExampleUser(t *testing.T) (*domain.User, error) {
	t.Helper()

	email := "user@example.com"
	serverHash := []byte("hash_example1234")
	serverSalt := []byte("salt_example1234")
	return domain.NewUser(email, serverHash, serverSalt)
}

// SetupTestUserRepository initializes a repository
func setupTestUserRepository(ctx context.Context, t *testing.T) *storage.SQLiteUserRepository {
	t.Helper()

	// Inizialize repository
	conn, _ := setupInitializedTestDB(ctx, t)
	repository := storage.NewSQLiteUserRepository(conn)

	return repository
}

func TestUserRepository_Save(t *testing.T) {
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

		if newUser.CreatedAt.IsZero()  {
			t.Errorf("Expected CreatedAt population, is empty")
		}
	})

}

func TestGet(t *testing.T) {
	ctx := context.Background()

	// Setup
	repo := setupTestUserRepository(ctx, t)
	newUser, err := createExampleUser(t)
	if err != nil { t.Fatalf("Error creating example user: %v", err) }

	if err := repo.Save(ctx, newUser); err != nil {
		t.Fatalf("Error saving credentials: %v", err)
	}

	tests := []struct {
		name			string
		id				uuid.UUID
		expectedError	error
	}{
		{
			name: "Success_GetById",
			id: newUser.ID,
			expectedError: nil,
		},{
			name: "Failure_ID_Inexistent",
			id: uuid.New(),
			expectedError: domain.ErrNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			retrieved, err := repo.Get(ctx, tt.id)

			if !errors.Is(err, tt.expectedError){
				t.Fatalf("Expected error '%v', got '%v'", tt.expectedError, err)
			}

			if tt.expectedError == nil {
				if retrieved == nil {
					t.Fatalf("Error getting user: %v", err)
				}

				if retrieved.ID != newUser.ID {
					t.Errorf("ID mismatch: expected %s, got %s", newUser.ID, retrieved.ID)
				}
				if retrieved.Email != newUser.Email {
					t.Errorf("Email mismatch: expected %v, got %v", newUser.Email, retrieved.Email)
				}
				if !bytes.Equal(retrieved.ServerHash, newUser.ServerHash) {
					t.Errorf("ServerHash mismatch")
				}
				if !bytes.Equal(retrieved.ServerSalt, newUser.ServerSalt) {
					t.Errorf("ServerSalt mismatch")
				}
			}
		})
	}
}

func TestGetByEmail(t *testing.T) {
	ctx := context.Background()

	// Setup
	repo := setupTestUserRepository(ctx, t)
	newUser, err := createExampleUser(t)
	if err != nil { t.Fatalf("Error creating example user: %v", err) }

	if err := repo.Save(ctx, newUser); err != nil {
		t.Fatalf("Error saving credentials: %v", err)
	}

	tests := []struct {
		name			string
		email			string
		expectedError	error
	}{
		{
			name: "Success_GetByEmail",
			email: newUser.Email,
			expectedError: nil,
		},{
			name: "Failure_Email_Inexistent",
			email: "wrong@example.com",
			expectedError: domain.ErrNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			retrieved, err := repo.GetByEmail(ctx, tt.email)

			if !errors.Is(err, tt.expectedError){
				t.Fatalf("Expected error '%v', got '%v'", tt.expectedError,err)
			}

			// Validate fields
			if tt.expectedError == nil {
				if retrieved == nil {
					t.Fatalf("Error getting user: %v", err)
				}

				if retrieved.ID != newUser.ID {
					t.Errorf("ID mismatch: expected %s, got %s", newUser.ID, retrieved.ID)
				}
				if retrieved.Email != newUser.Email {
					t.Errorf("Email mismatch: expected %v, got %v", newUser.Email, retrieved.Email)
				}
				if !bytes.Equal(retrieved.ServerHash, newUser.ServerHash) {
					t.Errorf("ServerHash mismatch")
				}
				if !bytes.Equal(retrieved.ServerSalt, newUser.ServerSalt) {
					t.Errorf("ServerSalt mismatch")
				}
			}
			
		})
	}
}