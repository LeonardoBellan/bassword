package service_test

import (
	"context"
	"errors"
	"testing"

	"github.com/LeonardoBellan/bassword/internal/server/domain"
	"github.com/LeonardoBellan/bassword/internal/server/service"
)

type FakeVaultRepository struct {
	vault         map[string]*domain.Credentials
	SimulateError bool 
}

func NewFakeVaultRepository(simulateError bool) *FakeVaultRepository {
	return &FakeVaultRepository{
		vault: make(map[string]*domain.Credentials),
		SimulateError: simulateError,
	}
}

var errSimulatedIO = errors.New("simulated database I/O error")

func (f *FakeVaultRepository) Save(ctx context.Context, cred *domain.Credentials) error {
	if f.SimulateError {
		return errSimulatedIO
	}
	
	f.vault[cred.ID] = cred
	return nil
}

func (f *FakeVaultRepository) GetByIdAndUser(ctx context.Context, id string, userID string) (*domain.Credentials, error) {
	if f.SimulateError {
		return nil, errSimulatedIO
	}

	cred, exists := f.vault[id]

	// Verify existence
	if !exists || cred.UserID != userID {
		return nil, domain.ErrNotFound
	}

	return cred, nil
}

func (f *FakeVaultRepository) GetByServiceAndUser(ctx context.Context, serviceName string, userID string) (*domain.Credentials, error) {
	if f.SimulateError {
		return nil, errSimulatedIO
	}

	for _, cred := range f.vault {
		if cred.UserID == userID && cred.ServiceName == serviceName {
			return cred, nil
		}
	}

	return nil, domain.ErrNotFound
}

func TestVaultService_Save (t *testing.T) {
	userID := "123e4567-e89b-12d3-a456-426614174000"
	serviceName := "service_example"
	encryptedData := []byte("encrypted_secret")

	tests := []struct {
		name              string
		userID            string
		serviceName       string
		encryptedData     []byte
		simulateRepoError bool
		expectedError     error
	}{
		{
			name: "Success_Save",
			userID: userID,
			serviceName: serviceName,
			encryptedData: encryptedData,
			simulateRepoError: false,
			expectedError: nil,
		},{
			name: "Failure_Domain_Error_Propagation",
			userID: "00000000-0000-0000-0000-0000000",
			serviceName: serviceName,
			encryptedData: encryptedData,
			simulateRepoError: false,
			expectedError: domain.ErrInvalidUserID,
		},{
			name: "Failure_Repository_Error_Propagation",
			userID: userID,
			serviceName: serviceName,
			encryptedData: encryptedData,
			simulateRepoError: true,
			expectedError: errSimulatedIO,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			fakeRepo := NewFakeVaultRepository(tt.simulateRepoError)

			vaultService := service.NewVaultService(fakeRepo)
			err := vaultService.Save(ctx, tt.userID, tt.serviceName, tt.encryptedData)

			if !errors.Is(err, tt.expectedError) {
				t.Errorf("Expected error '%v', got '%v'", tt.expectedError, err)
			}
		})
	} 
}

func TestVaultService_Get(t *testing.T) {
	userID := "123e4567-e89b-12d3-a456-426614174000"
	serviceName := "service_example"
	encryptedData := []byte("encrypted_secret")

	tests := []struct {
		name				string
		userID				string
		serviceName			string
		setupRepo			func(repo *FakeVaultRepository)
		simulateRepoError 	bool
		expectedError     	error
	}{
		{
			name: "Success_Get",
			userID: userID,
			serviceName: serviceName,
			setupRepo: func(repo *FakeVaultRepository) {
				
				cred,_ := domain.NewCredentials(userID, serviceName, encryptedData)
				_ = repo.Save(context.Background(), cred)
			},
			simulateRepoError: false,
			expectedError: nil,
		},{
			name: "Failure_Credentials_Not_Found",
			userID: userID,
			serviceName: serviceName,
			setupRepo: func(repo *FakeVaultRepository) {},
			simulateRepoError: false,
			expectedError: domain.ErrCredentialsNotFound,
		},{
			name: "Failure_Repository_Error_Propagation",
			userID: userID,
			serviceName: serviceName,
			setupRepo: func(repo *FakeVaultRepository) {},
			simulateRepoError: true,
			expectedError: errSimulatedIO,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			fakeRepo := NewFakeVaultRepository(tt.simulateRepoError)

			if tt.setupRepo != nil {
				tt.setupRepo(fakeRepo)
			}

			vaultService := service.NewVaultService(fakeRepo)

			creds, err := vaultService.GetForService(ctx, tt.serviceName, tt.userID)
			if !errors.Is(err, tt.expectedError) {
				t.Errorf("Expected error %v, got %v", tt.expectedError, err)
			}

			// Verify state
			if tt.expectedError == nil && creds == nil {
				t.Error("Expected credentials object, got nil")
			}
			if tt.expectedError != nil && creds != nil {
				t.Error("Expected nil credentials after error")
			}
		})
	}
}