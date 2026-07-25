package crypto

import (
	"bytes"
	"errors"
	"testing"

	"github.com/LeonardoBellan/bassword/internal/domain"
	"golang.org/x/crypto/argon2"
)

func TestHashSecret(t *testing.T) {
	secret := []byte("secret_password")
	t.Run("Success_Secret_Hashed", func (t *testing.T) {
		t.Parallel()
		
		hash, salt, err := HashSecret(secret)
		if err != nil {
			t.Fatalf("Error during secret hashing: %v", err)
		}

		if len(hash) != 32 {
			t.Errorf("Invalid Hash length: expected %v, got %v", 32, len(hash))
		}
		
		if len(salt) != 16 {
			t.Errorf("Invalid salt length: expected %v, got %v", 32, len(salt))
		}
	})

	t.Run("Success_Hash_And_Salt_Univocity", func (t *testing.T) {
		t.Parallel()
		
		hash1, salt1, err := HashSecret(secret)
		if err != nil {
			t.Fatalf("Error during secret hashing: %v", err)
		}

		hash2, salt2, err := HashSecret(secret)
		if err != nil {
			t.Fatalf("Error during secret hashing: %v", err)
		}

		if bytes.Equal(hash1, hash2) {
			t.Errorf("Error computed hashes are equal")
		}

		if bytes.Equal(salt1, salt2) {
			t.Error("Error generated salt is equal")
		}
	})

	t.Run("Success_Reproducibility", func (t *testing.T) {
		t.Parallel()
		
		hashComputed, salt, err := HashSecret(secret)
		if err != nil {
			t.Fatalf("Error during secret hashing: %v", err)
		}

		hashVerify := argon2.IDKey(secret, salt, 1, 64*1024, 4, 32)

		if !bytes.Equal(hashComputed, hashVerify) {
			t.Error("Error mismatch between hash using same salt")
		}
	})

	t.Run("Success_Empty_Secret", func (t *testing.T){
		t.Parallel()
		
		hash, salt, err := HashSecret([]byte{})
		if err != nil {
			t.Fatalf("Error during empty secret hashing: %v", err)
		}

		if len(hash) != 32 || len(salt) != 16{
			t.Errorf("Invalid hash or salt for empty secret")
		}
	})

	t.Run("Success_Nil_Secret", func (t *testing.T){
		t.Parallel()
		
		hash, salt, err := HashSecret(nil)
		if err != nil {
			t.Fatalf("Error during nil secret hashing: %v", err)
		}

		if len(hash) != 32 || len(salt) != 16{
			t.Errorf("Invalid hash or salt for nil secret")
		}
	})

}

func TestVerifyHash(t *testing.T) {
	secretCorrect := []byte("correct_secret_password")
	secretIncorrect := []byte("incorrect_secret_password")
	hash, salt, err := HashSecret(secretCorrect)
	if err != nil {
		t.Fatalf("Error during secret hashing: %v", err)
	}

	t.Run("Success_Correct_Secret", func (t *testing.T){
		t.Parallel()

		err = VerifyHash(secretCorrect, hash, salt); 
		if err != nil {
			t.Errorf("Error verifying hash: %v", err)
		}
	})

	t.Run("Failure_Incorrect_Secret", func (t *testing.T){
		t.Parallel()
		
		err = VerifyHash(secretIncorrect, hash, salt)
		if !errors.Is(err, domain.ErrMismatchedSecret) {
			t.Errorf("Error comparing secrets: expected %v, got %v", domain.ErrMismatchedSecret, err)
		}
	})

	t.Run("Failure_Incorrect_Salt", func (t *testing.T){
		t.Parallel()
		
		saltIncorrect := make([]byte,16)
		err = VerifyHash(secretCorrect, hash, saltIncorrect)
		if !errors.Is(err, domain.ErrMismatchedSecret) {
			t.Errorf("Error comparing secrets: expected %v, got %v", domain.ErrMismatchedSecret, err)
		}
	})

}

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
