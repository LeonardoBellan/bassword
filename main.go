package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/LeonardoBellan/bassword/internal/crypto"
	"github.com/LeonardoBellan/bassword/internal/db"
	"github.com/LeonardoBellan/bassword/internal/models"
)

func main() {
	password := []byte("PasswordFeisbuk")
	masterPassword := []byte("rewr!")
	
	/* Generate random sequence */
	salt := make([]byte,32)
	rand.Read(salt)

	/* Initialize DB */
	if err := db.InitDB("./database.db"); err != nil {
    	log.Fatal(err)
	}

	//Encrypt
	EncryptedData,err := crypto.Encrypt(password,masterPassword,[]byte(salt))
	if err != nil {
		panic(err.Error())
	}
	fmt.Println(hex.EncodeToString(EncryptedData))

	var newEntry models.CredentialEntry
	newEntry.ServiceName = "Facebook"
	newEntry.Username = "bell"
	newEntry.EncryptedData = EncryptedData
	newEntry.Salt = salt

	fmt.Println(newEntry)
	db.SavePassword(&newEntry)
	
	fmt.Println("Salvataggio avvenuto")

	getEntry,err := db.GetCredentialsByService("Facebook")
	if err != nil { panic(err.Error()) }

	fmt.Println("Ricezione avvenuta")

	//Decrypt
	masterPassword = []byte("rewr!")
	plaintext,err := crypto.Decrypt(getEntry.EncryptedData,masterPassword,getEntry.Salt)
	fmt.Println(getEntry)
	fmt.Println(string(plaintext))
}