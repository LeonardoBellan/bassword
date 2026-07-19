package domain

type User struct {
	ID          int    `json:"id"`
	Email       string `json:"email"`
	Server_Hash []byte `json:"server_hash"`
	Server_Salt []byte `json:"server_salt"`
}
