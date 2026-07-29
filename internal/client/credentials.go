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

type credentialsPayload struct {
	ServiceName   string `json:"service_name"`
	EncryptedData string `json:"encrypted_data"`
}