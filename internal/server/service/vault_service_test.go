package service_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/LeonardoBellan/bassword/internal/server/domain"
	"github.com/LeonardoBellan/bassword/internal/server/service"
	"github.com/google/uuid"
)

type FakeVaultRepository struct {
	vault         map[uuid.UUID]*domain.Credentials
	SimulateError bool 
}

func NewFakeVaultRepository(simulateError bool) *FakeVaultRepository {
	return &FakeVaultRepository{
		vault: make(map[uuid.UUID]*domain.Credentials),
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

func (f *FakeVaultRepository) GetByIdAndUser(ctx context.Context, id uuid.UUID, userID uuid.UUID) (*domain.Credentials, error) {
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

func (f *FakeVaultRepository) GetByServiceAndUser(ctx context.Context, serviceNameIndex []byte, userID uuid.UUID) (*domain.Credentials, error) {
	if f.SimulateError {
		return nil, errSimulatedIO
	}

	for _, cred := range f.vault {
		if cred.UserID == userID && bytes.Equal(cred.ServiceNameIndex, serviceNameIndex) {
			return cred, nil
		}
	}

	return nil, domain.ErrNotFound
}

func TestVaultService_Save (t *testing.T) {
	userID := uuid.New()
	serviceNameIndex := []byte("service_example")
	encryptedData := []byte("encrypted_secret")

	tests := []struct {
		name              string
		userID            uuid.UUID
		serviceNameIndex  []byte
		encryptedData     []byte
		simulateRepoError bool
		expectedError     error
	}{
		{
			name: "Success_Save",
			userID: userID,
			serviceNameIndex: serviceNameIndex,
			encryptedData: encryptedData,
			simulateRepoError: false,
			expectedError: nil,
		},{
			name: "Failure_Domain_Error_Propagation",
			userID: uuid.Nil,
			serviceNameIndex: serviceNameIndex,
			encryptedData: encryptedData,
			simulateRepoError: false,
			expectedError: domain.ErrInvalidUserID,
		},{
			name: "Failure_Repository_Error_Propagation",
			userID: userID,
			serviceNameIndex: serviceNameIndex,
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
			err := vaultService.Save(ctx, tt.userID, tt.serviceNameIndex, tt.encryptedData)

			if !errors.Is(err, tt.expectedError) {
				t.Errorf("Expected error '%v', got '%v'", tt.expectedError, err)
			}
		})
	} 
}

func TestVaultService_GetForService(t *testing.T) {
	userID := uuid.New()
	serviceNameIndex := []byte("service_example")
	encryptedData := []byte("encrypted_secret")

	tests := []struct {
		name				string
		userID				uuid.UUID
		serviceNameIndex			[]byte
		setupRepo			func(repo *FakeVaultRepository)
		simulateRepoError 	bool
		expectedError     	error
	}{
		{
			name: "Success_Get",
			userID: userID,
			serviceNameIndex: serviceNameIndex,
			setupRepo: func(repo *FakeVaultRepository) {
				
				cred,_ := domain.NewCredentials(userID, serviceNameIndex, encryptedData)
				_ = repo.Save(context.Background(), cred)
			},
			simulateRepoError: false,
			expectedError: nil,
		},{
			name: "Failure_Credentials_Not_Found",
			userID: userID,
			serviceNameIndex: serviceNameIndex,
			setupRepo: func(repo *FakeVaultRepository) {},
			simulateRepoError: false,
			expectedError: domain.ErrCredentialsNotFound,
		},{
			name: "Failure_Repository_Error_Propagation",
			userID: userID,
			serviceNameIndex: serviceNameIndex,
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

			creds, err := vaultService.GetForService(ctx, tt.serviceNameIndex, tt.userID)
			if !errors.Is(err, tt.expectedError) {
				t.Errorf("Expected error %v, got %v", tt.expectedError, err)
			}

			// Verify state
			if tt.expectedError == nil {
				if creds == nil {
					t.Error("Expected credentials object, got nil")
				} else {
					if creds.UserID != tt.userID {
						t.Errorf("Expected UserID %s, got %s", tt.userID, creds.UserID)
					}
					if !bytes.Equal(creds.ServiceNameIndex, tt.serviceNameIndex) {
						t.Errorf("ServiceNameIndex mismatch")
					}
					if !bytes.Equal(creds.EncryptedData, encryptedData){
						t.Errorf("Encrypted data mismatch")
					}
				}
			}
		})
	}
}
