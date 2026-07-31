package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"

	"golang.org/x/crypto/argon2"
)

type Argon2Configuration struct {
    HashRaw    []byte
    Salt       []byte
    TimeCost   uint32
    MemoryCost uint32
    Threads    uint8
    KeyLength  uint32
}

// Wipe zeroes the elements of the provided slice
func Wipe(slice []byte) {
    if slice == nil {
        return
    }
    for i := range slice {
        slice[i] = 0
    }
    runtime.KeepAlive(slice)
}

// GenerateSalt generates a random cryptographically secure salt of the provided size
// Returns the generated salt
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

// HashSecure receives an authHash and hashes it using argon2id
// Returns the computed hashKey and the salt used for hashing
func HashSecure(authHash []byte) (string, error) {
	config := &Argon2Configuration{
		TimeCost: 2,
		MemoryCost: 64*1024,
		Threads: 4,
		KeyLength: 32,
	}
	
	// Salt generation
	salt, err := GenerateSalt(16)
	if err != nil {
		return "", err
	}
	config.Salt = salt

	// Hash computing
	config.HashRaw = argon2.IDKey(
        authHash,
        config.Salt,
        config.TimeCost,
        config.MemoryCost,
        config.Threads,
        config.KeyLength,
    )

	// Format
	encodedHash := fmt.Sprintf(
        "$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
        argon2.Version,
        config.MemoryCost,
        config.TimeCost,
        config.Threads,
        base64.RawStdEncoding.EncodeToString(config.Salt),
        base64.RawStdEncoding.EncodeToString(config.HashRaw),
    )

	return encodedHash, nil
}

func parseArgon2Hash(encodedHash string) ( *Argon2Configuration, error ){
	components := strings.Split(encodedHash, "$")
	if len(components) != 6 {
		return nil, errors.New("Invalid hash format structure")
	}

	if !strings.HasPrefix(components[1], "argon2id") {
        return nil, errors.New("unsupported algorithm variant")
    }

	var version int
    fmt.Sscanf(components[2], "v=%d", &version)

    // Parse configuration parameters
    config := &Argon2Configuration{}
    fmt.Sscanf(components[3], "m=%d,t=%d,p=%d", 
        &config.MemoryCost, &config.TimeCost, &config.Threads)

    // Decode salt
    salt, err := base64.RawStdEncoding.DecodeString(components[4])
    if err != nil {
        return nil, fmt.Errorf("salt decoding failed: %w", err)
    }
    config.Salt = salt

    // Decode hash
    hash, err := base64.RawStdEncoding.DecodeString(components[5])
    if err != nil {
        return nil, fmt.Errorf("hash decoding failed: %w", err)
    }
    config.HashRaw = hash
    config.KeyLength = uint32(len(hash))

    return config, nil
}

// VerifyAuthHash compares expectedHash with hashed authHash + salt
// Returns ErrMismatchedSecret if the hash does not corrispond to expectedHash
func VerifySecretSecure(providedSecret []byte, storedHash string) error {

	// Parse stored hash
	config, err := parseArgon2Hash(storedHash)
	if err != nil { return err }

	// Compute providedSecret with same configuration
	computedHash := argon2.IDKey(
		providedSecret,
		config.Salt,
		config.TimeCost,
        config.MemoryCost,
        config.Threads,
        config.KeyLength,
	)

	// Compare hashes
	if subtle.ConstantTimeCompare(computedHash, config.HashRaw) != 1 {
		return ErrMismatchedSecret
	}

	return nil
}

// Encrypt a plaintext in AES-GCM using a derived key from the master password
// Returns the encrypted ciphertext
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

// Decrypt a ciphertext using an AES-GCM using a derived key from the master password
// Returns the decrypted plaintext
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