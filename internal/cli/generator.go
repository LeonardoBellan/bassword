package cli

import (
	"crypto/rand"
	"math/big"
)

// generateRandomPassword generates a random password securely
// Returns the generated password as []byte; the caller MUST defer crypto.Wipe() on it.
func generateRandomPassword(length int) ([]byte, error) {
	//Charset used for password and PIN generation
	const (
		lowerCharSet   = "abcdefghijklmnopqrstuvwxyz"
		upperCharSet   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		numberCharSet  = "0123456789"
		specialCharSet = "!@#$%^&*()-_=+,.?/:;{}[]~"
		allCharSet     = lowerCharSet + upperCharSet + numberCharSet + specialCharSet
	)

	password := make([]byte, length)
	charSetLength := big.NewInt(int64(len(allCharSet)))

	for i := 0; i<length; i++ {
		randomIdx,err := rand.Int(rand.Reader, charSetLength)
		if err != nil { return nil,err }

		password[i] = allCharSet[randomIdx.Int64()]
	}

	return password,nil
}

