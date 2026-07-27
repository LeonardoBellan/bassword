package service

import (
	"context"
	"errors"
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
	// Hash
	serverHash, serverSalt, err := crypto.HashAuthKey(authHash)
	if err != nil { return err }
	
	// Create user
	user,err := domain.NewUser(email,serverHash,serverSalt)
	if err != nil { return err }

	if err := s.repo.Save(ctx, user); err != nil {
		if errors.Is(err, domain.ErrConflict){
			return domain.ErrUserExists
		}

		return err
	}

	return nil
}

// s.Authenticates authenticates the user with the provided authHash by comparing it to the stored hash
// Returns a jwt token
func (s *AuthService) Authenticate(ctx context.Context, email string, authHash []byte) (string, error) {
	// Get user info on db	
	user, err := s.repo.GetByEmail(ctx, email)
	if err != nil { 
		if errors.Is(err, domain.ErrNotFound) {
			return "", domain.ErrUserNotFound
		}
		
		return "",err 
	}

	if err := crypto.VerifyAuthHash(authHash, user.ServerHash, user.ServerSalt); err != nil {
		return "", domain.ErrInvalidSecret
	}

	return s.tm.GenerateToken(user.ID, 15*time.Minute)
}