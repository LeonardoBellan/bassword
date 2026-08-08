package cli

import (
	"time"

	"github.com/LeonardoBellan/bassword/internal/client"
)

type AppState struct {
	Client           *client.Client
	Email			 string
	ClipboardTimeout time.Duration
}
