package client

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
)

type CryptoEngine struct {
	encryptionKey	[]byte	// Data encryption (AES-GCM)
	authKey []byte			// API Authentication (HMAC)
	blindIndexKey []byte	// Blind indexing (HMAC)
}

func NewCryptoEngine(masterPassword, salt []byte) (*CryptoEngine, error) {

	//if len(salt) < 16 {
	//	return nil, 
	//}

	// Master key derivation (argon2id)
	time := uint32(1)
	memory := uint32(64*1024)
	threads := uint8(4)
	keyLen := uint32(64)

	masterKey :=  argon2.IDKey(masterPassword, salt, time, memory, threads, keyLen)
	defer clear(masterKey)

	// Key Expansion
	hashFunc := sha256.New
	keyLength := hashFunc().Size()
	hEnc,err := hkdf.Key(hashFunc, masterKey, salt, "encryption", keyLength)
	if err != nil { return nil, err }
	hAuth, err := hkdf.Key(hashFunc, masterKey, salt, "authentication", keyLength)
	if err != nil { return nil, err }
	hBlindIndex, err := hkdf.Key(hashFunc, masterKey, salt, "blind_index", keyLength)
	if err != nil { return nil, err }

	// CryptoEngine setup
	engine := &CryptoEngine {
		encryptionKey: hEnc,
		authKey: hAuth,
		blindIndexKey: hBlindIndex,
	}

	return engine, nil
}

// Encrypt a plaintext in AES-GCM using a derived key from the master password
// Returns the encrypted ciphertext
func (ce *CryptoEngine) Encrypt(plaintext []byte) ([]byte,error) {

	// Initialize cipher
	block, err := aes.NewCipher(ce.encryptionKey)
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
func (ce *CryptoEngine) Decrypt(data []byte) ([]byte, error){

	// Initialize cipher
	block, err := aes.NewCipher(ce.encryptionKey)
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

func (ce *CryptoEngine) AuthKey() []byte {
	return ce.authKey
}

func (ce *CryptoEngine) ComputeBlindIndex(data []byte) []byte {
	mac := hmac.New(sha256.New, ce.blindIndexKey)
	mac.Write(data)

	return mac.Sum(nil)
}