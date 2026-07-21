package service

import (
	"context"
	"errors"

	"github.com/LeonardoBellan/bassword/internal/domain"
)

type VaultRepository interface {
	Save(ctx context.Context, credentials *domain.Credentials) error
	GetByIdAndUser(ctx context.Context, id int, userID int) (*domain.Credentials, error)
	GetByServiceAndUser(ctx context.Context, serviceName string, userID int) (*domain.Credentials,error)
}

type VaultService struct {
	repo VaultRepository
}

func NewVaultService(r VaultRepository) *VaultService {
	return &VaultService{repo:r}
}

func (s *VaultService) Save(ctx context.Context, userID int, serviceName string, encryptedData []byte) error{	
	credentials := domain.Credentials {
		UserID: userID,
		ServiceName: serviceName,
		EncryptedData: encryptedData,
	}

	if err := credentials.IsValid(); err != nil {
        return err
    }
	
	if err := s.repo.Save(ctx, &credentials); err != nil {
		return err
	}

	return nil
}

func (s *VaultService) GetForService(ctx context.Context, serviceName string, userID int) (*domain.Credentials, error) {	
	credentials,err := s.repo.GetByServiceAndUser(ctx, serviceName, userID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, domain.ErrCredentialsNotFound
		}
		return nil, err
	}

	return credentials, nil
}