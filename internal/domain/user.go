package domain

import "regexp"

type User struct {
	ID          int    `json:"id"`
	Email       string `json:"email"`
	ServerHash []byte `json:"server_hash"`
	ServerSalt []byte `json:"server_salt"`
}

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

func (u *User) IsValid() error {
	if u.Email == "" || !emailRegex.MatchString(u.Email) {
		return ErrInvalidEmail
	}
	if len(u.ServerHash) <= 0 {
		return ErrEmptyHash
	}
	if len(u.ServerSalt) <= 0 {
		return ErrEmptySalt
	}

	return nil
}