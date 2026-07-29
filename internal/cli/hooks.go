package cli

import (
	"github.com/LeonardoBellan/bassword/internal/shared/crypto"
)

func RequireMasterPassword(state *AppState) error {

	// Prompt master password
	masterPassword, err := securePrompt("Insert master password:")
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

	// Ask master password if it was not asked before
	if state.AuthHash == nil {
		RequireMasterPassword(state)
	}

	// Login
	if err := state.Client.Login(state.Email, state.AuthHash); err != nil {
		return err
	}

	return nil
}