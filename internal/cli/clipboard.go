package cli

import (
	"fmt"
	"time"

	"golang.design/x/clipboard"
)

// copyPasswordToClipboard manages user feedback 
func copyPasswordToClipboard(password []byte, timeout time.Duration) error {
	fmt.Printf("Password Copied to Clipboard, expires in%s...\n", timeout)
	return copyToClipboardAndWait(password, timeout)
}

// copyToClipboardAndWait writes in the clipboard and blocks execution until
// the timer ends or the user copies something
func copyToClipboardAndWait(text []byte, duration time.Duration) error {
	if err := clipboard.Init(); err != nil {
		return err
	}

	writeDone := clipboard.Write(clipboard.FmtText, text)

	select {
	case <-writeDone:
		return nil
	case <-time.After(duration):
		clipboard.Write(clipboard.FmtText, []byte(""))
		return nil
	}
}
