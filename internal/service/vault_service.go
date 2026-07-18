package service

import (
	"context"

	"github.com/LeonardoBellan/bassword/internal/models"
)

type VaultRepository interface {
	Save(ctx context.Context, credentials *models.Credentials) error
	GetByIdAndUser(ctx context.Context, id int, UserId int) (*models.Credentials)
	GetByServiceAndUser(ctx context.Context, serviceName string, userId int) (*models.Credentials,error)
}