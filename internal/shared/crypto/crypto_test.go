package crypto

import (
	"bytes"
	"errors"
	"testing"

	"github.com/LeonardoBellan/bassword/internal/server/domain"
	"golang.org/x/crypto/argon2"
)

func TestWipe(t *testing.T) {
	t.Run("Success_Wipe", func(t *testing.T) {
		data := []byte("slice")
		Wipe(data)

		for i, b := range data {
			if b != 0 {
				t.Fatalf("expected byte %d to be zero, got %d", i, b)
			}
		}
	})

	t.Run("Nil_No_Panic", func(t *testing.T) {
		defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Wipe(nil) panicked: %v", r)
		}
		}()

		Wipe(nil)
	})
}

func TestGenerateSalt(t *testing.T) {
	expectedSize := 16

	salt, err := GenerateSalt(expectedSize)
	if err != nil {
		t.Fatalf("Failure generating salt: %v", err)
	}

	t.Run("Salt_Length", func(t *testing.T) {
		if len(salt) != expectedSize {
			t.Errorf("Incorrect salt length: expected %d, got %d", expectedSize, len(salt))
		}
	})

	t.Run("Salt_Univocity", func(t *testing.T) {
		salt2, err := GenerateSalt(expectedSize)
		if err != nil {
			t.Fatalf("Failure generating salt2: %v", err)
		}

		if bytes.Equal(salt, salt2) {
			t.Error("Identical salt generated")
		}
	})

	t.Run("Salt_Not_Empty", func(t *testing.T) {
		emptyBytes := make([]byte, expectedSize)
		if bytes.Equal(salt, emptyBytes) {
			t.Error("Generated salt is slice of 0")
		}
	})
}

func TestDeriveKeys(t *testing.T) {
	secret := []byte("secret_password")
	salt := []byte("user@example.com")
	encryptionKey, authHash := DeriveKeys(secret, salt)

	t.Run("Keys_Salt", func(t *testing.T) {
		if len(encryptionKey) != 32 {
			t.Errorf("Invalid encryption key length: expected %v, got %v", 32, len(encryptionKey))
		}
		
		if len(authHash) != 32 {
			t.Errorf("Invalid auth hash length: expected %v, got %v", 32, len(authHash))
		}
	})

	t.Run("Keys_Reproducibility", func(t *testing.T) {
		t.Parallel()

		encryptionKey2, authHash2 := DeriveKeys(secret, salt)

		if !bytes.Equal(encryptionKey, encryptionKey2){
			t.Errorf("Encryption key mismatch")
		}

		if !bytes.Equal(authHash, authHash2){
			t.Errorf("Auth hash mismatch")
		}
	})

	t.Run("Success_Empty_Secret", func (t *testing.T){
		t.Parallel()
		
		encryptionKey, authHash := DeriveKeys([]byte{}, salt)

		if len(encryptionKey) != 32 || len(authHash) != 32 {
			t.Errorf("Invalid key or hash for empty secret")
		}
	})

	t.Run("Success_Nil_Secret", func (t *testing.T){
		t.Parallel()
		
		encryptionKey, authHash := DeriveKeys(nil, salt)

		if len(encryptionKey) != 32 || len(authHash) != 32 {
			t.Errorf("Invalid key or hash for nil secret")
		}
	})
}

func TestHashAuthKey(t *testing.T) {
	secret := []byte("secret_password")
	hash, salt, err := HashAuthKey(secret)
	if err != nil {
		t.Fatalf("Error during secret hashing: %v", err)
	}

	t.Run("Hash_Salt_Length", func (t *testing.T) {
		if len(hash) != 32 {
			t.Errorf("Invalid Hash length: expected %v, got %v", 32, len(hash))
		}
		
		if len(salt) != 16 {
			t.Errorf("Invalid salt length: expected %v, got %v", 32, len(salt))
		}
	})

	t.Run("Hash_Salt_Univocity", func (t *testing.T) {
		t.Parallel()

		hash2, salt2, err := HashAuthKey(secret)
		if err != nil {
			t.Fatalf("Error during secret hashing: %v", err)
		}

		if bytes.Equal(hash, hash2) {
			t.Errorf("Error computed hashes are equal")
		}

		if bytes.Equal(salt, salt2) {
			t.Error("Error generated salt is equal")
		}
	})

	t.Run("Success_Reproducibility", func (t *testing.T) {
		t.Parallel()

		hashVerify := argon2.IDKey(secret, salt, 1, 64*1024, 4, 32)

		if !bytes.Equal(hash, hashVerify) {
			t.Error("Error mismatch between hash using same salt")
		}
	})

	t.Run("Success_Empty_Secret", func (t *testing.T){
		t.Parallel()
		
		hash, salt, err := HashAuthKey([]byte{})
		if err != nil {
			t.Fatalf("Error during empty secret hashing: %v", err)
		}

		if len(hash) != 32 || len(salt) != 16{
			t.Errorf("Invalid hash or salt for empty secret")
		}
	})

	t.Run("Success_Nil_Secret", func (t *testing.T){
		t.Parallel()
		
		hash, salt, err := HashAuthKey(nil)
		if err != nil {
			t.Fatalf("Error during nil secret hashing: %v", err)
		}

		if len(hash) != 32 || len(salt) != 16{
			t.Errorf("Invalid hash or salt for nil secret")
		}
	})

}

func TestVerifyAuthHash(t *testing.T) {
	secretCorrect := []byte("correct_secret_password")
	secretIncorrect := []byte("incorrect_secret_password")
	hash, salt, err := HashAuthKey(secretCorrect)
	if err != nil {
		t.Fatalf("Error during secret hashing: %v", err)
	}

	t.Run("Success_Correct_Secret", func (t *testing.T){
		t.Parallel()

		err = VerifyAuthHash(secretCorrect, hash, salt); 
		if err != nil {
			t.Errorf("Error verifying hash: %v", err)
		}
	})

	t.Run("Failure_Incorrect_Secret", func (t *testing.T){
		t.Parallel()
		
		err = VerifyAuthHash(secretIncorrect, hash, salt)
		if !errors.Is(err, domain.ErrMismatchedSecret) {
			t.Errorf("Error comparing secrets: expected %v, got %v", domain.ErrMismatchedSecret, err)
		}
	})

	t.Run("Failure_Incorrect_Salt", func (t *testing.T){
		t.Parallel()
		
		saltIncorrect := make([]byte,16)
		err = VerifyAuthHash(secretCorrect, hash, saltIncorrect)
		if !errors.Is(err, domain.ErrMismatchedSecret) {
			t.Errorf("Error comparing secrets: expected %v, got %v", domain.ErrMismatchedSecret, err)
		}
	})

}

func TestEncrypt(t *testing.T) {
	masterKey := bytes.Repeat([]byte("k"), 32)
	plaintext := []byte("correct-horse-battery-staple")

	t.Run("Success", func(t *testing.T) {
		// Encryption
		_, err := Encrypt(plaintext, masterKey)
		if err != nil {
			t.Errorf("Encryption failed: %v", err) 
		}
	})

	t.Run("Success_Univocity", func(t *testing.T) {
		ciphertext1, err := Encrypt(plaintext, masterKey)
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}

		ciphertext2, err := Encrypt(plaintext, masterKey)
		if err != nil {
			t.Fatalf("Encrypt failed second time: %v", err)
		}

		if bytes.Equal(ciphertext1, ciphertext2) {
			t.Fatal("expected different ciphertexts for same inputs, got identical outputs")
		}
	})

	t.Run("Success_Empty_Plaintext", func(t *testing.T) {
		// Encryption
		_, err := Encrypt([]byte{}, masterKey)
		if err != nil {
			t.Errorf("Encryption failed for empty plaintext: %v", err) 
		}
	})
	t.Run("Failure_Empty_Key", func(t *testing.T) {
		// Encryption
		_, err := Encrypt(plaintext, []byte{})
		if err == nil {
			t.Errorf("Expected error for empty key, got nil") 
		}
	})
}

func TestDecrypt(t *testing.T){
	masterKey := bytes.Repeat([]byte("k"), 32)
	plaintext := []byte("correct-horse-battery-staple")
	ciphertext, err := Encrypt(plaintext, masterKey)
	if err != nil { t.Fatalf("Failed setup, cannot encrypt")}

	tests := []struct {
		name				string
		encryptedData		[]byte
		key					[]byte
		expectedError		bool
	}{
		{
			name: "Success",
			encryptedData: ciphertext,
			key: masterKey,
			expectedError: false,
		},
		{
			name: "Failure_Wrong_Key",
			encryptedData: ciphertext,
			key: bytes.Repeat([]byte("x"), 32),
			expectedError: true,
		},
		{
			name: "Failure_Tampered_Ciphertext",
			encryptedData: ciphertext[:len(ciphertext)-1],		// Remove last byte
			key: masterKey,
			expectedError: true,
		},
		{
			name: "Failure_Invalid_Ciphertext",
			encryptedData: []byte("short"),
			key: masterKey,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := Decrypt(tt.encryptedData, tt.key)
            
            // Expected failure
            if tt.expectedError {
                if err == nil {
                    t.Errorf("Expected error, got nil")
                }
                return
            }

            // Expected success
            if err != nil {
                t.Fatalf("Error: %v", err)
            }
            
            if !bytes.Equal(result, plaintext) {
                t.Errorf("Wrong decrypted data. Expected: %s, got: %s", plaintext, result)
            }
		})
	}
}
