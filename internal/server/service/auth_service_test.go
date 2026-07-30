package service_test

import (
	"context"
	"errors"
	"testing"

	"github.com/LeonardoBellan/bassword/internal/server/domain"
	"github.com/LeonardoBellan/bassword/internal/server/service"
)

type FakeUserRepository struct {
	user         map[string]*domain.User
	SimulateError bool 
}

func NewFakeUserRepository(simulateError bool) *FakeUserRepository {
	return &FakeUserRepository{
		user: make(map[string]*domain.User),
		SimulateError: simulateError,
	}
}

func (f *FakeUserRepository) Save(ctx context.Context, user *domain.User) error {
	if f.SimulateError {
		return errSimulatedIO
	}
	
	f.user[user.ID] = user
	return nil
}

func (f *FakeUserRepository) Get(ctx context.Context, id string) (*domain.User, error) {
	if f.SimulateError {
		return nil, errSimulatedIO
	}

	user, exists := f.user[id]

	// Verify existence
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

func TestUserService_Save (t *testing.T) {
	ID := "123e4567-e89b-12d3-a456-426614174000"
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
			fakeRepo := NewFakeUserRepository(tt.simulateRepoError)

			userService := service.NewUserService(fakeRepo)
			err := userService.Save(ctx, tt.userID, tt.serviceName, tt.encryptedData)

			if !errors.Is(err, tt.expectedError) {
				t.Errorf("Expected error '%v', got '%v'", tt.expectedError, err)
			}
		})
	} 
}

func TestUserService_Get(t *testing.T) {
	userID := "123e4567-e89b-12d3-a456-426614174000"
	serviceName := "service_example"
	encryptedData := []byte("encrypted_secret")

	tests := []struct {
		name				string
		userID				string
		serviceName			string
		setupRepo			func(repo *FakeUserRepository)
		simulateRepoError 	bool
		expectedError     	error
	}{
		{
			name: "Success_Get",
			userID: userID,
			serviceName: serviceName,
			setupRepo: func(repo *FakeUserRepository) {
				
				cred,_ := domain.NewUser(userID, serviceName, encryptedData)
				_ = repo.Save(context.Background(), cred)
			},
			simulateRepoError: false,
			expectedError: nil,
		},{
			name: "Failure_User_Not_Found",
			userID: userID,
			serviceName: serviceName,
			setupRepo: func(repo *FakeUserRepository) {},
			simulateRepoError: false,
			expectedError: domain.ErrUserNotFound,
		},{
			name: "Failure_Repository_Error_Propagation",
			userID: userID,
			serviceName: serviceName,
			setupRepo: func(repo *FakeUserRepository) {},
			simulateRepoError: true,
			expectedError: errSimulatedIO,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			fakeRepo := NewFakeUserRepository(tt.simulateRepoError)

			if tt.setupRepo != nil {
				tt.setupRepo(fakeRepo)
			}

			userService := service.NewUserService(fakeRepo)

			creds, err := userService.GetForService(ctx, tt.serviceName, tt.userID)
			if !errors.Is(err, tt.expectedError) {
				t.Errorf("Expected error %v, got %v", tt.expectedError, err)
			}

			// Verify state
			if tt.expectedError == nil && creds == nil {
				t.Error("Expected user object, got nil")
			}
			if tt.expectedError != nil && creds != nil {
				t.Error("Expected nil user after error")
			}
		})
	}
}