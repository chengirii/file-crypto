package aes_file

import (
	"encoding/hex"
	"fmt"
	ecies "github.com/ecies/go/v2"
	"log"
	"testing"
)

const PublicKey = "03350c307b4771243cd40184bb9120404c96119033998ea147944b85d3e17f2c6a"
const PrivateKey = "6e7486d1ceb447c3c63cba76268e3b6b072b861abaa59fe84df49da7ed74b71f"

func TestGenerateEciesKey(t *testing.T) {
	k, err := ecies.GenerateKey()
	if err != nil {
		panic(err)
	}
	fmt.Println("PublicKey:", k.PublicKey.Hex(true))
	fmt.Println("PrivateKey:", k.Hex())
}

func EncryptData(s []byte) string {
	publicKey, _ := ecies.NewPublicKeyFromHex(PublicKey)
	encryptedData, _ := ecies.Encrypt(publicKey, s)
	return hex.EncodeToString(encryptedData)
}

func DecodeData(s string) ([]byte, error) {
	cryptoData, _ := hex.DecodeString(s)
	privateKey, _ := ecies.NewPrivateKeyFromHex(PrivateKey)
	encodeData, err := ecies.Decrypt(privateKey, cryptoData)
	return encodeData, err
}

func TestEcies(t *testing.T) {
	msg := "Hello World!"
	fmt.Println("Raw Data", msg)
	EncryptedDataHex := EncryptData([]byte(msg))
	fmt.Println("EncryptedDataHex:", EncryptedDataHex)
	data, err := DecodeData(EncryptedDataHex)
	if err != nil {
		log.Println(err)
	}
	fmt.Println("DecodeData:", string(data))
}
