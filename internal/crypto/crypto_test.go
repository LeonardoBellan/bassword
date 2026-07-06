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

func TestEncryptDecrypt_EmptyPlaintext(t *testing.T) {
	masterPassword := []byte("correct horse battery staple")
	salt := []byte("0123456789abcdef")

	ciphertext, err := Encrypt([]byte{}, masterPassword, salt)
	if err != nil {
		t.Fatalf("Encrypt failed for empty plaintext: %v", err)
	}

	result, err := Decrypt(ciphertext, masterPassword, salt)
	if err != nil {
		t.Fatalf("Decrypt failed for empty plaintext: %v", err)
	}

	if len(result) != 0 {
		t.Fatalf("expected empty plaintext, got %q", result)
	}
}

func TestDecrypt_WrongPassword(t *testing.T) {
	plaintext := []byte("my secret")
	masterPassword := []byte("correct horse battery staple")
	wrongPassword := []byte("wrong horse battery staple")
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

func TestDecrypt_InvalidCiphertext(t *testing.T) {
	masterPassword := []byte("correct horse battery staple")
	salt := []byte("0123456789abcdef")

	_, err := Decrypt([]byte("short"), masterPassword, salt)
	if err == nil {
		t.Fatal("Decrypt succeeded with invalid ciphertext, expected failure")
	}
}

func TestEncrypt_SameInputsProduceDifferentCiphertexts(t *testing.T) {
	plaintext := []byte("my secret")
	masterPassword := []byte("correct horse battery staple")
	salt := []byte("0123456789abcdef")

	ciphertext1, err := Encrypt(plaintext, masterPassword, salt)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	ciphertext2, err := Encrypt(plaintext, masterPassword, salt)
	if err != nil {
		t.Fatalf("Encrypt failed second time: %v", err)
	}

	if bytes.Equal(ciphertext1, ciphertext2) {
		t.Fatal("expected different ciphertexts for same inputs, got identical outputs")
	}
}

func TestDecrypt_WrongSalt(t *testing.T) {
	plaintext := []byte("my secret")
	masterPassword := []byte("correct horse battery staple")
	salt := []byte("0123456789abcdef")
	wrongSalt := []byte("fedcba9876543210")

	ciphertext, err := Encrypt(plaintext, masterPassword, salt)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	_, err = Decrypt(ciphertext, masterPassword, wrongSalt)
	if err == nil {
		t.Fatal("Decrypt succeeded with wrong salt, expected failure")
	}
}

func TestDecrypt_TamperedCiphertext(t *testing.T) {
	plaintext := []byte("my secret")
	masterPassword := []byte("correct horse battery staple")
	salt := []byte("0123456789abcdef")

	ciphertext, err := Encrypt(plaintext, masterPassword, salt)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	ciphertext[len(ciphertext)-1] ^= 0x01
	_, err = Decrypt(ciphertext, masterPassword, salt)
	if err == nil {
		t.Fatal("Decrypt succeeded with tampered ciphertext, expected failure")
	}
}

func TestWipe_ZeroizesSlice(t *testing.T) {
	data := []byte("secret")
	Wipe(data)

	for i, b := range data {
		if b != 0 {
			t.Fatalf("expected byte %d to be zero, got %d", i, b)
		}
	}
}

func TestWipe_NilDoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Wipe(nil) panicked: %v", r)
		}
	}()

	Wipe(nil)
}
