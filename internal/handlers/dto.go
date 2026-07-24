package handlers

import (
	"regexp"

	"github.com/LeonardoBellan/bassword/internal/domain"
)

type AuthRequest struct {
	Email   string 	`json:"email"`
	AuthHash string `json:"auth_hash"`
}

func (req *AuthRequest) IsValid() error {
	// Validate input
	var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(req.Email) {
		return domain.ErrInvalidEmail
	}
	if len(req.AuthHash) == 0 {
		return domain.ErrEmptyHash
	}

	return nil
}

type LoginResponse struct {
	Status string    `json:"status"`
	Data   LoginData `json:"data"`
}

type LoginData struct {
	Token string    `json:"token"`
}