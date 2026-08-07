package cli

import (
	"errors"
	"fmt"

	"github.com/LeonardoBellan/bassword/internal/client"
	"github.com/LeonardoBellan/bassword/internal/shared/crypto"
)

func RequireMasterPassword(state *AppState) error {

	// Prompt master password
	masterPassword, err := securePrompt("Insert master password: ")
	if err != nil {
		return err
	}

	// Save keys in app state
	state.EncryptionKey, state.AuthHash = crypto.DeriveKeys(masterPassword, []byte(state.Email))

	return nil
}

func RequireLogin(state *AppState) error {

	// Already logged
	if state.Client.Token != "" {
		return nil
	}

	if state.Email == "" {
		return client.ErrNotRegistered
	}

	// Ask master password if it was not asked before
	if state.AuthHash == nil {
		RequireMasterPassword(state)
	}

	// Login
	if err := state.Client.Login(state.Email, state.AuthHash); err != nil {        
		if errors.Is(err, client.ErrUnauthorized) {
			return fmt.Errorf("Invalid credentials. Please try again.")
		}

		return err
	}

	return nil
}