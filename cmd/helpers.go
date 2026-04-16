package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"golang.design/x/clipboard"

	"github.com/LeonardoBellan/bassword/internal/crypto"
	"github.com/LeonardoBellan/bassword/internal/db"
	"golang.org/x/term"
)

func askPassword(prompt string) ([]byte, error) {
	fmt.Print(prompt)
	pass, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	return pass, err
}

func copyToClipboardWithTimeout(text []byte, duration time.Duration) (<-chan struct{}, error) {
	if err := clipboard.Init(); err != nil {
		return nil,err
	}
	writeDone := clipboard.Write(clipboard.FmtText, text)

	expected := make([]byte, len(text))
	copy(expected, text)

	//Wait and clear clipboard content if it has not changed
	go func() {
		defer crypto.Wipe(expected)
		time.Sleep(duration)
		if err := clipboard.Init(); err != nil {
			return
		}
		current := clipboard.Read(clipboard.FmtText)
		if bytes.Equal(current, expected) {
			clearDone := clipboard.Write(clipboard.FmtText, []byte(""))
			<-clearDone
		}
	}()

	return writeDone,nil
}

// copyPasswordToClipboard securely copies the password to clipboard with timeout and user feedback.
func copyPasswordToClipboard(password []byte, timeout time.Duration) error {
	writeDone, err := copyToClipboardWithTimeout(password, timeout)
	if err != nil {
		return err
	}
	fmt.Println("Password inserted into clipboard, expires in ", timeout)
	<-writeDone
	return nil
}

// getMasterPassword securely prompts for the master password.
// Returns the password as []byte; the caller MUST defer crypto.Wipe() on it.
func getMasterPassword() ([]byte, error) {
	return askPassword("Insert master password: ")
}

// ensureDBOpen opens the DB and handles initialization errors.
func ensureDBOpen(ctx context.Context, dbPath string) error {
	err := db.OpenDB(ctx, dbPath)
	if err != nil {
		if !errors.Is(err, db.ErrDBNotInitialized) {
			return err
		}
		return fmt.Errorf("DB not initialized, run bassword init")
	}
	return nil
}

// closeDB closes the DB and returns any error.
func closeDB() error {
	return db.CloseDB()
}