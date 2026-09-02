package service

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/LeonardoBellan/bassword/internal/server/domain"
	"github.com/LeonardoBellan/bassword/internal/server/auth"
	"github.com/LeonardoBellan/bassword/internal/server/crypto"
)

type UserRepository interface {
	Save(ctx context.Context, user *domain.User) error
	Get(ctx context.Context, id uuid.UUID) (*domain.User, error)
	GetByEmail(ctx context.Context, email string) (*domain.User, error)
}

type AuthService struct {
	repo UserRepository
	tm *auth.TokenManager
}

func NewAuthService(r UserRepository, tm *auth.TokenManager) *AuthService {
	return &AuthService{
		repo:r,
		tm: tm,
	}

}

// s.Register saves a new user by hashing the provided authHash
func (s *AuthService) Register(ctx context.Context, email string, authHash []byte) error {
	// Hash
	secretHash, err := crypto.HashSecure(authHash)
	if err != nil { return err }
	
	// Create user
	user,err := domain.NewUser(email, secretHash)
	if err != nil { return err }

	if err := s.repo.Save(ctx, user); err != nil {
		if errors.Is(err, domain.ErrConflict){
			return domain.ErrUserExists
		}

		return err
	}

	return nil
}

// s.Authenticate authenticates the user with the provided authHash by comparing it to the stored hash
// Returns a jwt token
func (s *AuthService) Authenticate(ctx context.Context, email string, authHash []byte) (string, error) {
	// Get user info on db	
	user, err := s.repo.GetByEmail(ctx, email)
	if err != nil { 
		if errors.Is(err, domain.ErrNotFound) {
			return "", domain.ErrUserNotFound
		}
		
		return "", err 
	}

	if err := crypto.VerifySecretSecure(authHash, user.SecretHash); err != nil {
		
		return "", domain.ErrInvalidSecret
	}

	return s.tm.GenerateToken(user.ID)
}
