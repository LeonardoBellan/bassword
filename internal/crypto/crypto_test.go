package crypto

import (
	"bytes"
	"testing"
)

func TestEncryptDecrypt_Success(t *testing.T) {
	plaintext := []byte("my secret")
	masterPassword := []byte("correct horse battery staple")
	salt := []byte("0123456789abcdef")

	plaintextCopy := append([]byte(nil), plaintext...)

	ciphertext, err := Encrypt(plaintextCopy, masterPassword, salt)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	result, err := Decrypt(ciphertext, masterPassword, salt)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(result, plaintext) {
		t.Fatalf("decrypted plaintext mismatch: got %q, want %q", result, plaintext)
	}
}

func TestDecrypt_WrongPassword(t *testing.T) {
	plaintext := []byte("my secret")
	masterPassword := []byte("correct horse battery staple")
	wrongPassword := []byte("battery horse correct staple")
	salt := []byte("0123456789abcdef")

	ciphertext, err := Encrypt(plaintext, masterPassword, salt)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	_, err = Decrypt(ciphertext, wrongPassword, salt)
	if err == nil {
		t.Fatal("Decrypt succeeded with wrong password, expected failure")
	}
}
