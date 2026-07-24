package service

import (
	"context"
	"time"

	"github.com/LeonardoBellan/bassword/internal/crypto"
	"github.com/LeonardoBellan/bassword/internal/domain"
)

type UserRepository interface {
	Save(ctx context.Context, user *domain.User) error
	Get(ctx context.Context, id int) (*domain.User, error)
	GetByEmail(ctx context.Context, email string) (*domain.User, error)
}

type AuthService struct {
	repo UserRepository
	tm *crypto.TokenManager
}

func NewAuthService(r UserRepository, tm *crypto.TokenManager) *AuthService {
	return &AuthService{
		repo:r,
		tm: tm,
	}

}

func (s *AuthService) Register(ctx context.Context, email string, authHash []byte) error {

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


func (s *AuthService) Authenticate(ctx context.Context, email string, authHash []byte) (string, error) {
	// Get user info on db	
	user, err := s.repo.GetByEmail(ctx, email)
	if err != nil { return "",err }

	if err := crypto.VerifyHash(authHash, user.ServerHash, user.ServerSalt); err != nil {
		return "",err
	}

	token, err := s.tm.GenerateToken(user.ID, 15*time.Minute)
	return token, nil
}