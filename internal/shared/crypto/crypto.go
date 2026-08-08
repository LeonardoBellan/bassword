package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
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

// GenerateSalt generates a random cryptographically secure salt of the provided size
// Returns the generated salt
func GenerateSalt(size int) ([]byte, error) {
	salt := make([]byte, size)
	if _,err := rand.Read(salt); err != nil {
		return nil, err
	}

	return salt, nil
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
