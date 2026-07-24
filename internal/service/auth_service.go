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
	
	// TODO - Check email existence

	// Hash
	serverHash, serverSalt, err := crypto.HashSecret(authHash)
	if err != nil { return err }
	
	// Create user
	user,err := domain.NewUser(email,serverHash,serverSalt)
	if err != nil { return err }

	return s.repo.Save(ctx, user)
}


func (s *AuthService) Authenticate(ctx context.Context, email string, authHash []byte) (string, error) {
	// Get user info on db	
	user, err := s.repo.GetByEmail(ctx, email)
	if err != nil { return "",err }

	if err := crypto.VerifyHash(authHash, user.ServerHash, user.ServerSalt); err != nil {
		return "",err
	}

	return s.tm.GenerateToken(user.ID, 15*time.Minute)
}