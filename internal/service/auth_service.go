package service

import (
	"context"

	"github.com/LeonardoBellan/bassword/internal/models"
)

type UserRepository interface {
	Save(ctx context.Context, user *models.User) error
	Get(ctx context.Context, id int) (*models.User,error)
}