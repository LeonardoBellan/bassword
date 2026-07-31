package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/LeonardoBellan/bassword/internal/server/domain"
	"github.com/LeonardoBellan/bassword/internal/server/service"
	"github.com/LeonardoBellan/bassword/internal/shared/crypto"
	"github.com/google/uuid"
)

type FakeUserRepository struct {
	user             map[uuid.UUID]*domain.User
	SimulateError    bool
	SimulateConflict bool
}

func NewFakeUserRepository(simulateError bool, simulateConflict bool) *FakeUserRepository {
	return &FakeUserRepository{
		user:             make(map[uuid.UUID]*domain.User),
		SimulateError:    simulateError,
		SimulateConflict: simulateConflict,
	}
}

func (f *FakeUserRepository) Save(ctx context.Context, user *domain.User) error {
	if f.SimulateError {
		return errSimulatedIO
	}
	if f.SimulateConflict {
		return domain.ErrConflict
	}

	f.user[user.ID] = user
	return nil
}

func (f *FakeUserRepository) Get(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	if f.SimulateError {
		return nil, errSimulatedIO
	}

	user, exists := f.user[id]
	if !exists {
		return nil, domain.ErrNotFound
	}
	return user, nil
}

func (f *FakeUserRepository) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	if f.SimulateError {
		return nil, errSimulatedIO
	}

	for _, user := range f.user {
		if user.Email == email {
			return user, nil
		}
	}
	return nil, domain.ErrNotFound
}

func TestAuthService_Register(t *testing.T) {
	email := "test@example.com"
	authHash := []byte("secret-auth-hash")

	tests := []struct {
		name             string
		email            string
		authHash         []byte
		simulateError    bool
		simulateConflict bool
		expectedError    error
	}{
		{
			name:             "Success_Register",
			email:            email,
			authHash:         authHash,
			simulateError:    false,
			simulateConflict: false,
			expectedError:    nil,
		},
		{
			name:             "Failure_User_Already_Exists",
			email:            email,
			authHash:         authHash,
			simulateError:    false,
			simulateConflict: true,
			expectedError:    domain.ErrUserExists,
		},
		{
			name:             "Failure_Repository_Error",
			email:            email,
			authHash:         authHash,
			simulateError:    true,
			simulateConflict: false,
			expectedError:    errSimulatedIO,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			fakeRepo := NewFakeUserRepository(tt.simulateError, tt.simulateConflict)
			
			tm, err := crypto.NewTokenManager("jwt-key", 10*time.Minute)
			if err != nil {
				t.Fatalf("Failure creating token manager")
			}
			
			authService := service.NewAuthService(fakeRepo, tm)

			err = authService.Register(ctx, tt.email, tt.authHash)

			if !errors.Is(err, tt.expectedError) {
				t.Errorf("Expected error '%v', got '%v'", tt.expectedError, err)
			}
		})
	}
}

func TestAuthService_Authenticate(t *testing.T) {
	email := "test@example.com"
	validAuthHash := []byte("correct-secret-hash")
	invalidAuthHash := []byte("wrong-secret-hash")

	tests := []struct {
		name          string
		email         string
		authHash      []byte
		setupRepo     func(repo *FakeUserRepository)
		simulateError bool
		expectedError error
	}{
		{
			name:     "Success_Authenticate",
			email:    email,
			authHash: validAuthHash,
			setupRepo: func(repo *FakeUserRepository) {
				secret, _ := crypto.HashSecure(validAuthHash)
				user, _ := domain.NewUser(email, secret)
				_ = repo.Save(context.Background(), user)
			},
			simulateError: false,
			expectedError: nil,
		},
		{
			name:     "Failure_User_Not_Found",
			email:    "nonexistent@example.com",
			authHash: validAuthHash,
			setupRepo: func(repo *FakeUserRepository) {
			},
			simulateError: false,
			expectedError: domain.ErrUserNotFound,
		},
		{
			name:     "Failure_Invalid_Secret",
			email:    email,
			authHash: invalidAuthHash, // Password errata
			setupRepo: func(repo *FakeUserRepository) {
				secret, _ := crypto.HashSecure(validAuthHash)
				user, _ := domain.NewUser(email, secret)
				_ = repo.Save(context.Background(), user)
			},
			simulateError: false,
			expectedError: domain.ErrInvalidSecret,
		},
		{
			name:     "Failure_Repository_Error",
			email:    email,
			authHash: validAuthHash,
			setupRepo: func(repo *FakeUserRepository) {},
			simulateError: true,
			expectedError: errSimulatedIO,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			fakeRepo := NewFakeUserRepository(tt.simulateError, false)

			if tt.setupRepo != nil {
				tt.setupRepo(fakeRepo)
			}

			tm, err := crypto.NewTokenManager("jwt-key", 10*time.Minute)
			if err != nil {
				t.Fatalf("Failure creating token manager")
			}
			authService := service.NewAuthService(fakeRepo, tm)

			token, err := authService.Authenticate(ctx, tt.email, tt.authHash)

			if !errors.Is(err, tt.expectedError) {
				t.Errorf("Expected error '%v', got '%v'", tt.expectedError, err)
			}

			// Verify token state
			if tt.expectedError == nil && token == "" {
				t.Error("Expected a valid JWT token, got empty string")
			}
			if tt.expectedError != nil && token != "" {
				t.Errorf("Expected empty token on error, got '%s'", token)
			}
		})
	}
}