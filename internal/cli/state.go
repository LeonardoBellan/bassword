package cli

import (
	"time"

	"github.com/LeonardoBellan/bassword/internal/client"
)

type AppState struct {
	Client           *client.Client
	Email			 string
	EncryptionKey    []byte
	AuthHash         []byte
	ClipboardTimeout time.Duration
}