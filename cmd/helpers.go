package cmd

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"golang.design/x/clipboard"

	"github.com/LeonardoBellan/bassword/internal/crypto"
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
		fmt.Println("Erasing clipboard")
		current := clipboard.Read(clipboard.FmtText)
		if bytes.Equal(current, expected) {
			clearDone := clipboard.Write(clipboard.FmtText, []byte(""))
			<-clearDone
		}
	}()

	return writeDone,nil
}