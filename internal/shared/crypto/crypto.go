package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"io"
	"runtime"

	"golang.org/x/crypto/argon2"
)

/* Zeroes a slice to remove it from memory */
func Wipe(slice []byte) {
    if slice == nil {
        return
    }
    for i := range slice {
        slice[i] = 0
    }
    runtime.KeepAlive(slice)
}

func GenerateSalt(size int) ([]byte, error) {
	salt := make([]byte, size)
	if _,err := rand.Read(salt); err != nil {
		return nil, err
	}

	return salt, nil
}

// DeriveKey derives a 64-bit key from the master password using argon2id used for key separation
// Returns the encryptionKey and the authHash
func DeriveKeys(secret, salt []byte) ([]byte, []byte) {
	keyMaterial :=  argon2.IDKey(secret, salt, 1, 64*1024, 4, 64)

	encryptionKey := keyMaterial[:32]
	authHash := keyMaterial[32:]

	return encryptionKey, authHash
}

// HashAuthKey receives an authHash and hashes it using argon2id
// Returns the computed hashKey and the salt used for hashing
func HashAuthKey(authHash []byte) ([]byte, []byte, error) {
	salt, err := GenerateSalt(16)
	if err != nil {
		return nil, nil, err
	}

	serverHash := argon2.IDKey(authHash, salt, 1, 64*1024, 4, 32)
	return serverHash, salt, nil
}

// VerifyAuthHash compares expectedHash with hashed authHash + salt
// Returns ErrMismatchedSecret if the hash does not corrispond to expectedHash
func VerifyAuthHash(authHash []byte, expectedHash []byte, salt []byte) error {
	// Compute given secret
	computedHash := argon2.IDKey(authHash, salt, 1, 64*1024, 4, 32)

	// Compare hashes
	if subtle.ConstantTimeCompare(computedHash, expectedHash) != 1 {
		return ErrMismatchedSecret
	}

	return nil
}

// Encrypt plaintext password in AES-GCM using a derived key from the master password
// Returns
func Encrypt(plaintext []byte, masterKey []byte) ([]byte,error) {

	// Initialize cipher
	block, err := aes.NewCipher(masterKey)
	if err != nil { return nil,err }

	aesgcm, err := cipher.NewGCM(block)
	if err != nil { return nil,err }

	// Generate nonce
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil,err
	}

	// Final package: nonce + ciphertext
	data := aesgcm.Seal(nonce, nonce, plaintext, nil)
	return data, nil
}

func Decrypt(data []byte, masterKey []byte) ([]byte, error){

	// Initialize cipher
	block, err := aes.NewCipher(masterKey)
	if err != nil { return nil,err }
	aesgcm, err := cipher.NewGCM(block)
	if err != nil { return nil,err }

	// Extract nonce from package data
	nonceSize := aesgcm.NonceSize()
	if len(data)<nonceSize {
		return nil, errors.New("Invalid ciphertext: too short")
	}
	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]

	plaintext,err := aesgcm.Open(nil,nonce,ciphertext,nil)
	if err != nil { return nil,err }

	return plaintext,nil
}