package service

import (
	"context"

	"github.com/LeonardoBellan/bassword/internal/crypto"
	"github.com/LeonardoBellan/bassword/internal/domain"
)

type UserRepository interface {
	Save(ctx context.Context, user *domain.User) error
	Get(ctx context.Context, id int) (*domain.User, error)
	GetByEmail(ctx context.Context, email string) (*domain.User, error)
}

type UserService struct {
	repo UserRepository
}

func NewUserService(r UserRepository) *UserService {
	return &UserService{repo:r}
}

func (s *UserService) Register(ctx context.Context, email string, authHash []byte) error {

	serverHash, salt, err := crypto.HashSecret(authHash)
	if err != nil { return err }

	user := domain.User {
		Email: email,
		ServerHash: serverHash,
		ServerSalt: salt,
	}

	if err := user.IsValid(); err != nil {
        return err
    }

	if err := s.repo.Save(ctx, &user); err != nil {
		return err
	}

	return nil
}


func (s *UserService) Authenticate(ctx context.Context, email string, authHash []byte) (int,error) {
	// Get user info on db	
	user, err := s.repo.GetByEmail(ctx, email)
	if err != nil { return 0,err }

	if err := crypto.VerifySecret(authHash, user.ServerHash, user.ServerSalt); err != nil {
		return 0,err
	}

	return user.ID, nil
}