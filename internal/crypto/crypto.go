package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
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
    // runtime.KeepAlive assicura che il compilatore non ottimizzi 
    // eliminando lo slice prima che il ciclo sia finito.
    runtime.KeepAlive(slice)
}

/* Derives a 32-bit key from the master password */
func deriveKey(password []byte, salt []byte) []byte{
	key := argon2.IDKey(password, salt, 1, 64*1024, 4, 32)
	defer Wipe(password)
	return key	
}

/* Encypts plaintext password in AES-GCM using a derived key from the master password */
func Encrypt(plaintext []byte, masterPassword []byte, salt []byte) ([]byte,error) {
	
	// Clean passwords from memory after execution
	defer Wipe(plaintext)
	defer Wipe(masterPassword)
	
	//Derive key from master password
	key := deriveKey(masterPassword,salt)	

	/******* Initialize AES-GCM cipher with derived key *******/
	block, err := aes.NewCipher(key)
	if err != nil { return nil,err }

	aesgcm, err := cipher.NewGCM(block)
	if err != nil { return nil,err }

	Wipe(key)	// Clean key from memory

	//Generate nonce
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil,err
	}

	// Final package: nonce(12B) + ciphertext
	data := aesgcm.Seal(nonce, nonce, plaintext, nil)
	return data, nil
}

func Decrypt(data []byte, masterPassword []byte, salt []byte) ([]byte,error){
	// Clean passwords from memory after execution
	defer Wipe(masterPassword)
	
	//Derive key from master password
	key := deriveKey(masterPassword,salt)	

	/******* Initialize AES-GCM cipher with derived key *******/
	block, err := aes.NewCipher(key)
	if err != nil { return nil,err }
	aesgcm, err := cipher.NewGCM(block)
	if err != nil { return nil,err }

	Wipe(key)	// Clean key from memory

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