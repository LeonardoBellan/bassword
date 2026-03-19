package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
)

/* Derives a 32-bit key from the master password */
func deriveKey(password []byte, salt []byte) []byte{
	key := argon2.IDKey(password, salt, 1, 64*1024, 4, 32)

	/* Clean password from memory */
	for i:= range password{
		password[i] = 0
	}
	return key	
}

/* Encypts plaintext password in AES-GCM using a derived key from the master password */
func Encrypt(plaintext []byte, masterPassword []byte, salt []byte) ([]byte,error) {
	
	// Clean passwords from memory after execution
	defer func() {
        for i := range plaintext { plaintext[i] = 0 }
        for i := range masterPassword { masterPassword[i] = 0 }
    }()
	
	//Derive key from master password
	key := deriveKey(masterPassword,salt)	

	/******* Initialize AES-GCM cipher with derived key *******/
	block, err := aes.NewCipher(key)
	if err != nil { return nil,err }

	aesgcm, err := cipher.NewGCM(block)
	if err != nil { return nil,err }

	// Clean key from memory
	for i := range key{
		key[i] = 0
	}

	//Generate nonce
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil,err
	}

	// Final package: nonce(12B)+ciphertext(16B)
	data := aesgcm.Seal(nonce, nonce, plaintext, nil)
	return data, nil
}

func Decrypt(data []byte, masterPassword []byte, salt []byte) ([]byte,error){
// Deriva chiave -> Crea AES-GCM -> Ottieni plaintext

	// Clean passwords from memory after execution
	defer func() {
        for i := range masterPassword { masterPassword[i] = 0 }
    }()
	
	//Derive key from master password
	key := deriveKey(masterPassword,salt)	

	/******* Initialize AES-GCM cipher with derived key *******/
	block, err := aes.NewCipher(key)
	if err != nil { return nil,err }

	aesgcm, err := cipher.NewGCM(block)
	if err != nil { return nil,err }

	// Clean key from memory
	for i := range key{
		key[i] = 0
	}

	// Extract nonce from package data
	nonceSize := aesgcm.NonceSize()
	if len(data)<nonceSize {
		return nil,errors.New("Ciphertext troppo corto")
	}
	nonce,ciphertext := data[:nonceSize],data[nonceSize:]

	plaintext,err := aesgcm.Open(nil,nonce,ciphertext,nil)
	if err != nil { return nil,err }

	return plaintext,nil
}