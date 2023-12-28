package aes_file

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
)

func generateKeyPair() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

func savePEMKey(fileName string, key *rsa.PrivateKey) error {
	file, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer file.Close()

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(key)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	return pem.Encode(file, block)
}

func savePEMKeyPublic(fileName string, pubkey *rsa.PublicKey) error {
	file, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer file.Close()

	pubkeyBytes, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return err
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubkeyBytes,
	}

	return pem.Encode(file, block)
}

func readPEMKey(fileName string) (*rsa.PrivateKey, error) {
	file, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(file)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func readPEMKeyPublic(fileName string) (*rsa.PublicKey, error) {
	file, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(file)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing public key")
	}

	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	pubKey, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("failed to cast parsed public key to *rsa.PublicKey")
	}

	return pubKey, nil
}

func encryptMessage(message []byte, publicKey *rsa.PublicKey) ([]byte, error) {
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, message)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

func decryptMessage(ciphertext []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, ciphertext)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func TestRsa(t *testing.T) {
	//Uncomment this block if you want to generate new keys
	//privateKey, publicKey, err := generateKeyPair()
	//if err != nil {
	//	fmt.Println("Error generating key pair:", err)
	//	return
	//}
	//
	//err = savePEMKey("private.pem", privateKey)
	//if err != nil {
	//	fmt.Println("Error saving private key:", err)
	//	return
	//}
	//
	//err = savePEMKeyPublic("public.pem", publicKey)
	//if err != nil {
	//	fmt.Println("Error saving public key:", err)
	//	return
	//}

	// Uncomment this block if you want to read existing keys from files
	privateKey, err := readPEMKey("private.pem")
	if err != nil {
		fmt.Println("Error reading private key:", err)
		return
	}

	publicKey, err := readPEMKeyPublic("public.pem")
	if err != nil {
		fmt.Println("Error reading public key:", err)
		return
	}

	message := []byte("Hello, RSA encryption and decryption!")

	// Encrypt the message using the public key
	ciphertext, err := encryptMessage(message, publicKey)
	if err != nil {
		fmt.Println("Error encrypting message:", err)
		return
	}

	fmt.Printf("Encrypted Message: %x\n", ciphertext)

	// Decrypt the message using the private key
	plaintext, err := decryptMessage(ciphertext, privateKey)
	if err != nil {
		fmt.Println("Error decrypting message:", err)
		return
	}

	fmt.Println("Decrypted Message:", string(plaintext))
}
