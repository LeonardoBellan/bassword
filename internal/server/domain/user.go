package domain

type User struct {
	ID         int    `json:"id"`
	Email      string `json:"email"`
	ServerHash []byte `json:"server_hash"`
	ServerSalt []byte `json:"server_salt"`
}

func NewUser(email string, serverHash, serverSalt []byte) (*User, error) {
	if email == "" {
		return nil, ErrInvalidEmail
	}
	if len(serverHash) == 0 {
		return nil, ErrEmptyHash
	}
	if len(serverSalt) == 0 {
		return nil, ErrEmptySalt
	}

	return &User{
		Email:      email,
		ServerHash: serverHash,
		ServerSalt: serverSalt,
	}, nil
}