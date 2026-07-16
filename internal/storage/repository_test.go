package storage

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/LeonardoBellan/bassword/internal/models"
)


func TestAddPasswordAndGetCredentialsByService(t *testing.T) {
	path := openTempDB(t)
	ctx := context.Background()

	err := OpenDB(ctx, path)
	if !errors.Is(err, ErrDBNotInitialized) {
		t.Fatalf("expected ErrDBNotInitialized from OpenDB, got %v", err)
	}

	masterPassword := []byte("master-password")
	if err := InitializeDB(ctx, append([]byte(nil), masterPassword...)); err != nil {
		t.Fatalf("InitializeDB failed: %v", err)
	}

	entry := &models.CredentialEntry{
		ServiceName: "example.com",
		Username:    "user@example.com",
	}
	password := []byte("super-secret")

	if err := AddPassword(ctx, append([]byte(nil), masterPassword...), append([]byte(nil), password...), entry); err != nil {
		t.Fatalf("AddPassword failed: %v", err)
	}

	retrieved, err := GetCredentialsByService(ctx, append([]byte(nil), masterPassword...), entry.ServiceName)
	if err != nil {
		t.Fatalf("GetCredentialsByService failed: %v", err)
	}
	if string(retrieved) != string(password) {
		t.Fatalf("expected password %q, got %q", password, retrieved)
	}
}

func TestAddPassword_UpdatesExistingEntry(t *testing.T) {
	path := openTempDB(t)
	ctx := context.Background()

	err := OpenDB(ctx, path)
	if !errors.Is(err, ErrDBNotInitialized) {
		t.Fatalf("expected ErrDBNotInitialized from OpenDB, got %v", err)
	}

	masterPassword := []byte("master-password")
	if err := InitializeDB(ctx, append([]byte(nil), masterPassword...)); err != nil {
		t.Fatalf("InitializeDB failed: %v", err)
	}

	entry := &models.CredentialEntry{
		ServiceName: "example.com",
		Username:    "user@example.com",
	}

	if err := AddPassword(ctx, append([]byte(nil), masterPassword...), []byte("first-secret"), entry); err != nil {
		t.Fatalf("AddPassword failed first time: %v", err)
	}

	if err := AddPassword(ctx, append([]byte(nil), masterPassword...), []byte("second-secret"), entry); err != nil {
		t.Fatalf("AddPassword failed second time: %v", err)
	}

	retrieved, err := GetCredentialsByService(ctx, append([]byte(nil), masterPassword...), entry.ServiceName)
	if err != nil {
		t.Fatalf("GetCredentialsByService failed: %v", err)
	}
	if string(retrieved) != "second-secret" {
		t.Fatalf("expected updated password %q, got %q", "second-secret", retrieved)
	}
}

func TestGetCredentialsByService_WrongPasswordFails(t *testing.T) {
	path := openTempDB(t)
	ctx := context.Background()

	err := OpenDB(ctx, path)
	if !errors.Is(err, ErrDBNotInitialized) {
		t.Fatalf("expected ErrDBNotInitialized from OpenDB, got %v", err)
	}

	masterPassword := []byte("master-password")
	if err := InitializeDB(ctx, append([]byte(nil), masterPassword...)); err != nil {
		t.Fatalf("InitializeDB failed: %v", err)
	}

	entry := &models.CredentialEntry{
		ServiceName: "example.com",
		Username:    "user@example.com",
	}

	if err := AddPassword(ctx, append([]byte(nil), masterPassword...), []byte("secret"), entry); err != nil {
		t.Fatalf("AddPassword failed: %v", err)
	}

	_, err = GetCredentialsByService(ctx, []byte("wrong-password"), entry.ServiceName)
	if err == nil {
		t.Fatal("expected GetCredentialsByService to fail with wrong password")
	}
}

func TestGetCredentialsByService_NonExistentService(t *testing.T) {
	path := openTempDB(t)
	ctx := context.Background()

	err := OpenDB(ctx, path)
	if !errors.Is(err, ErrDBNotInitialized) {
		t.Fatalf("expected ErrDBNotInitialized from OpenDB, got %v", err)
	}

	masterPassword := []byte("master-password")
	if err := InitializeDB(ctx, append([]byte(nil), masterPassword...)); err != nil {
		t.Fatalf("InitializeDB failed: %v", err)
	}

	_, err = GetCredentialsByService(ctx, append([]byte(nil), masterPassword...), "missing-service")
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected sql.ErrNoRows for missing service, got %v", err)
	}
}

func TestCloseDB_NoPanicWhenNotOpen(t *testing.T) {
	if err := CloseDB(); err != nil {
		t.Fatalf("expected CloseDB to succeed when no DB open, got %v", err)
	}
}
