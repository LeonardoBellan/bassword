package cli

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

func askPassword(prompt string) ([]byte, error) {
	fmt.Print(prompt)
	pass, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	return pass, err
}

// getMasterPassword securely prompts for the master password.
// Returns the password as []byte; the caller MUST defer crypto.Wipe() on it.
func getMasterPassword() ([]byte, error) {
	return askPassword("Insert master password: ")
}

// getPlaintextPassword prompts for a service's password.
// Returns the password as []byte; the caller MUST defer crypto.Wipe() on it.
func getPlaintextPassword(serviceName string) ([]byte, error) {
	return askPassword(fmt.Sprintf("Insert password for %s: ", serviceName))
}