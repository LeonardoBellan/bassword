package service

import (
	"context"
)

type UserRepository interface {
	Save(ctx context.Context, user *domain.User) error
	Get(ctx context.Context, id int) (*domain.User,error)
}