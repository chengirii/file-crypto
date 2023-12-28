package aes_file

import (
	"fmt"
	ecies "github.com/ecies/go/v2"
	"testing"
)

func TestGenerateEciesKey(t *testing.T) {
	k, err := ecies.GenerateKey()
	if err != nil {
		panic(err)
	}
	fmt.Println("PublicKey:", k.PublicKey.Hex(true))
	fmt.Println("PrivateKey", k.Hex())
}
