package aes_file

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	ecies "github.com/ecies/go/v2"
	"os"
	"path/filepath"
	"strings"
)

const (
	eachEncryptLen   = 1024 * 1024 * 100 // Unencrypted 1 byte, encrypted to 32 bytes  100MB
	aesKeySize       = 32
	encryptedFileExt = ".cc"
	decryptedFileExt = "decrypted_"
)

func EncryptFile(filePath string, publicKeyHex string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer f.Close()
	fileInfo, _ := f.Stat()
	fileSize := fileInfo.Size()
	fmt.Println("File size to be encrypted:", fileSize, "bytes")

	forNum := fileSize / int64(eachEncryptLen) // encryption number
	if fileSize%int64(eachEncryptLen) != 0 {
		forNum++
	}
	//加密后存储的文件
	encryptedFilePath := filepath.Base(filePath) + encryptedFileExt
	encryptedFile, err := os.Create(encryptedFilePath)
	if err != nil {
		return fmt.Errorf("failed to create encrypted file: %v", err)
	}
	defer encryptedFile.Close()

	writer := bufio.NewWriter(encryptedFile)

	// AES密钥加密
	aesKey := make([]byte, aesKeySize)
	rand.Read(aesKey)

	// AES encryption Data
	// For 16, 24, and 32-bit strings, they correspond to AES-128, AES-192, and AES-256 encryption methods, respectively

	buffer := make([]byte, eachEncryptLen)
	for i := int64(0); i < forNum; i++ {
		n, err := f.Read(buffer)
		if err != nil {
			return fmt.Errorf("failed to read file: %v", err)
		}
		encryptedData, err := EncryptByAes(buffer[:n], aesKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt data: %v", err)
		}
		writer.WriteString(encryptedData)
		writer.Flush()

	}
	// writer Last
	publicKey, _ := ecies.NewPublicKeyFromHex(publicKeyHex)
	cryptoPwdKey, _ := ecies.Encrypt(publicKey, aesKey)
	writer.WriteString(hex.EncodeToString(cryptoPwdKey))
	writer.Flush()

	encryptedFileInfo, _ := encryptedFile.Stat()
	fmt.Printf("File encryption successful. Encrypted file name: %s, File size: %v bytes \n", encryptedFilePath, encryptedFileInfo.Size())
	return nil
}

func DecryptFile(filePath string, privateKeyHex string) (err error) {
	var keySize int64 = 258
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer f.Close()
	fileInfo, _ := f.Stat()
	fileSize := fileInfo.Size()
	fmt.Println("File size to be decrypted:", fileSize, "bytes")

	if fileSize < keySize {
		return fmt.Errorf("file is too small to contain the AES key")
	}
	aesKeyBytes := make([]byte, keySize)
	_, err = f.ReadAt(aesKeyBytes, fileSize-keySize)
	if err != nil {
		return fmt.Errorf("failed to read AES key: %v", err)
	}

	aesKeyBytes, _ = hex.DecodeString(string(aesKeyBytes))
	privateKey, _ := ecies.NewPrivateKeyFromHex(privateKeyHex)
	aesKey, err := ecies.Decrypt(privateKey, aesKeyBytes)
	if err != nil {
		return fmt.Errorf("decrypt aes fail : %v", err)
	}
	decryptedFilePath := decryptedFileExt + strings.TrimSuffix(filepath.Base(filePath), encryptedFileExt)
	decryptedFile, err := os.Create(decryptedFilePath)
	if err != nil {
		return fmt.Errorf("failed to create decrypted file: %v", err)
	}
	defer decryptedFile.Close()

	writer := bufio.NewWriter(decryptedFile)

	dataSize := fileSize - keySize
	forNum := dataSize / int64(eachEncryptLen) // encryption number
	if dataSize%int64(eachEncryptLen) != 0 {
		forNum++
	}

	_, err = f.Seek(0, os.SEEK_SET)
	buffer := make([]byte, eachEncryptLen)

	for i := int64(0); i < forNum; i++ {
		if i == forNum-1 { // Last iteration
			buffer = make([]byte, dataSize%eachEncryptLen)
		}
		n, err := f.Read(buffer)
		if err != nil {
			return fmt.Errorf("failed to read file: %v", err)
		}
		decryptedData, err := DecryptByAes(buffer[:n], aesKey)
		if err != nil {
			return fmt.Errorf("failed to decrypt data: %v", err)
		}
		writer.Write(decryptedData)
		writer.Flush()
	}
	decryptedFileInfo, _ := decryptedFile.Stat()
	fmt.Printf("File decryption successful. Decrypted file name: %s, File size: %v bytes \n", decryptedFileInfo.Name(), decryptedFileInfo.Size())
	return nil
}
