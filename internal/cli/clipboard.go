package cli

import (
	"fmt"
	"os/exec"
	"runtime"
	"time"

	"github.com/LeonardoBellan/bassword/internal/shared/crypto"
	"golang.design/x/clipboard"
)

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

func copyToClipboardWithTimeout(text []byte, duration time.Duration) (<-chan struct{}, error) {
	if err := clipboard.Init(); err != nil {
		return nil, err
	}
	writeDone := clipboard.Write(clipboard.FmtText, text)

	startClipboardClearWorker(text, duration)

	return writeDone, nil
}

func startClipboardClearWorker(text []byte, duration time.Duration) {
	copyData := make([]byte, len(text))
	copy(copyData, text)
	defer crypto.Wipe(copyData)

	if runtime.GOOS == "windows" {
		command := fmt.Sprintf("Start-Sleep -Seconds %d; Set-Clipboard -Value ''", int(duration.Seconds()))
		cmd := exec.Command("cmd", "/C", "start", "/B", "powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", command)
		_ = cmd.Start()
		return
	}

	go func() {
		defer crypto.Wipe(copyData)
		time.Sleep(duration)
		if err := clipboard.Init(); err != nil {
			return
		}
		clearDone := clipboard.Write(clipboard.FmtText, []byte(""))
		<-clearDone
	}()
}