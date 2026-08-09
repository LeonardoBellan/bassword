package client

import "fmt"

type Credentials struct {
	Username string `json:"user"`
	Password []byte `json:"pwd"`
}

func NewCredentials(username string, password []byte) (*Credentials, error) {
	if username == "" {
		return nil, fmt.Errorf("Empty username")
	}
	if len(password) == 0 {
		return nil, fmt.Errorf("Empty password")
	}

	return &Credentials{
		Username: username,
		Password: password,
	}, nil
}

// API DTO
type credentialsPayload struct {
	ServiceIndex   []byte `json:"service_name_index"`
	ServiceEncrypted []byte `json:"service_name_encrypted"`
	PayloadEncrypted []byte `json:"payload_encrypted"`
}
