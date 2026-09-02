package crypto

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

/* func TestWipe(t *testing.T) {
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
} */ 

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

/* func TestDeriveKeys(t *testing.T) {
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
}*/

func TestHashSecure(t *testing.T) {
	secret := []byte("secret_password")
	hashPHC, err := HashSecure(secret)
	if err != nil {
		t.Fatalf("Error during secret hashing: %v", err)
	}

	t.Run("PHC_Format", func(t *testing.T) {
		if !strings.HasPrefix(hashPHC, "$argon2id$v=19$m=65536,t=2,p=4$") {
			t.Errorf("Invalid PHC prefix format: got %v", hashPHC)
		}

		parts := strings.Split(hashPHC, "$")
		if len(parts) != 6 {
			t.Fatalf("Invalid PHC parts count: expected 6, got %d", len(parts))
		}

		if len(parts[4]) == 0 {
			t.Error("Salt portion in PHC is empty")
		}

		if len(parts[5]) == 0 {
			t.Error("Hash portion in PHC is empty")
		}
	})

	t.Run("Hash_Univocity", func(t *testing.T) {
		t.Parallel()

		hashPHC2, err := HashSecure(secret)
		if err != nil {
			t.Fatalf("Error during secret hashing: %v", err)
		}

		if hashPHC == hashPHC2 {
			t.Errorf("Error: computed hashes are identically salted")
		}
	})

	t.Run("Success_Reproducibility", func(t *testing.T) {
		t.Parallel()

		parts := strings.Split(hashPHC, "$")
		if len(parts) != 6 {
			t.Fatalf("Malformed PHC string for reproducibility test")
		}

		saltB64 := parts[4]
		hashB64 := parts[5]

		decodedSalt, err := base64.RawStdEncoding.DecodeString(saltB64)
		if err != nil {
			t.Fatalf("Error decoding salt from base64: %v", err)
		}

		// Recompute hash using same parameters
		hashVerifyRaw := argon2.IDKey(secret, decodedSalt, 2, 64*1024, 4, 32)
		hashVerifyB64 := base64.RawStdEncoding.EncodeToString(hashVerifyRaw)

		if hashB64 != hashVerifyB64 {
			t.Error("Error: mismatch between re-computed hash using extracted salt")
		}
	})

	t.Run("Success_Empty_Secret", func(t *testing.T) {
		t.Parallel()

		hash, err := HashSecure([]byte{})
		if err != nil {
			t.Fatalf("Error during empty secret hashing: %v", err)
		}

		if !strings.HasPrefix(hash, "$argon2id$") {
			t.Errorf("Invalid PHC format for empty secret")
		}
	})

	t.Run("Success_Nil_Secret", func(t *testing.T) {
		t.Parallel()

		hash, err := HashSecure(nil)
		if err != nil {
			t.Fatalf("Error during nil secret hashing: %v", err)
		}

		if !strings.HasPrefix(hash, "$argon2id$") {
			t.Errorf("Invalid PHC format for nil secret")
		}
	})
}

func TestVerifySecretSecure(t *testing.T) {
	secretCorrect := []byte("correct_secret_password")
	secretIncorrect := []byte("incorrect_secret_password")

	hashPHC, err := HashSecure(secretCorrect)
	if err != nil {
		t.Fatalf("Error during secret hashing: %v", err)
	}

	t.Run("Success_Correct_Secret", func(t *testing.T) {
		t.Parallel()

		err = VerifySecretSecure(secretCorrect, hashPHC)
		if err != nil {
			t.Errorf("Error verifying hash: %v", err)
		}
	})

	t.Run("Failure_Incorrect_Secret", func(t *testing.T) {
		t.Parallel()

		err = VerifySecretSecure(secretIncorrect, hashPHC)
		if !errors.Is(err, ErrMismatchedSecret) {
			t.Errorf("Error comparing secrets: expected %v, got %v", ErrMismatchedSecret, err)
		}
	})

	t.Run("Failure_Incorrect_Salt", func(t *testing.T) {
		t.Parallel()

		components := strings.Split(hashPHC, "$")
		if len(components) != 6 {
			t.Fatalf("Invalid PHC format generated by HashSecure")
		}

		components[4] = "AAAAAAAAAAAAAAAAAAAAAA"
		tamperedHashPHC := strings.Join(components, "$")

		err = VerifySecretSecure(secretCorrect, tamperedHashPHC)
		if !errors.Is(err, ErrMismatchedSecret) {
			t.Errorf("Error comparing secrets with wrong salt: expected %v, got %v", ErrMismatchedSecret, err)
		}
	})

	t.Run("Failure_Malformed_Hash", func(t *testing.T) {
		t.Parallel()

		// Verifichiamo che il parsing iniziale fallisca correttamente
		err = VerifySecretSecure(secretCorrect, "invalid_hash_string")
		if err == nil {
			t.Errorf("Expected error for malformed hash string, got nil")
		}
	})
}
/* func TestEncrypt(t *testing.T) {
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
}*/
