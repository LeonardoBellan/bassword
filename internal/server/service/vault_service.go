package service

import (
	"context"
	"errors"

	"github.com/LeonardoBellan/bassword/internal/server/domain"
)

type VaultRepository interface {
	Save(ctx context.Context, credentials *domain.Credentials) error
	GetByIdAndUser(ctx context.Context, id string, userID string) (*domain.Credentials, error)
	GetByServiceAndUser(ctx context.Context, serviceName string, userID string) (*domain.Credentials,error)
}

type VaultService struct {
	repo VaultRepository
}

func NewVaultService(r VaultRepository) *VaultService {
	return &VaultService{repo:r}
}

func (s *VaultService) Save(ctx context.Context, userID string, serviceName string, encryptedData []byte) error{	

	credentials, err := domain.NewCredentials(userID, serviceName, encryptedData)
	if err != nil { return err }

	return s.repo.Save(ctx, credentials)
}

func (s *VaultService) GetForService(ctx context.Context, serviceName string, userID string) (*domain.Credentials, error) {	
	credentials,err := s.repo.GetByServiceAndUser(ctx, serviceName, userID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, domain.ErrCredentialsNotFound
		}
		return nil, err
	}

	return credentials, nil
}