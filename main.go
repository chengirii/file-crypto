package main

import (
	aes "file-crypto/aes_file"
	"log"
)

func main() {
	err := aes.EncryptFile("./pe.iso", "0334aeb11565d3819cf516d62f3c7c0bd7d6c885460916d1ad52bf38edd4d2addc")
	if err != nil {
		log.Println(err)
	}
	err = aes.DecryptFile("./pe.iso.cc", "039792b6dc38ae423b9f360f6225af60d523dd0e769a2b61a52f9e0c96f794ea")
	if err != nil {
		log.Println(err)
	}
}
