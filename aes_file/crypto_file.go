package aes_file

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	ecies "github.com/ecies/go/v2"
	"github.com/schollz/progressbar/v3"
)

const (
	plainChunkSize   = 1024 * 1024 * 10 // 10MB raw chunk
	aesBlockSize     = 16
	aesKeySize       = 32
	encryptedFileExt = ".cc"
	decryptedPrefix  = "decrypted_"

	// ECIES-encrypted 32-byte AES key, hex-encoded.
	// 65 (uncompressed pubkey) + 16 (IV) + 32 (ciphertext) + 16 (tag) = 129 bytes -> 258 hex chars.
	wrappedKeyHexLen = 258
)

// PKCS7 always adds a full block when input is a multiple of the block size,
// so each full plain chunk produces (plainChunkSize + aesBlockSize) ciphertext bytes,
// then hex-encoded to twice the size.
const encryptedChunkHexLen = (plainChunkSize + aesBlockSize) * 2

// EncryptFile encrypts filePath with a fresh AES-256 key, then wraps the AES key
// with the given ECIES public key and appends it (hex-encoded) to the output file.
func EncryptFile(filePath, publicKeyHex string) error {
	publicKey, err := ecies.NewPublicKeyFromHex(publicKeyHex)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	aesKey := make([]byte, aesKeySize)
	if _, err := rand.Read(aesKey); err != nil {
		return fmt.Errorf("generate AES key: %w", err)
	}

	in, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("open file: %w", err)
	}
	defer in.Close()

	info, err := in.Stat()
	if err != nil {
		return fmt.Errorf("stat file: %w", err)
	}
	fileSize := info.Size()
	fmt.Println("File size to be encrypted:", fileSize, "bytes")

	outPath := filepath.Base(filePath) + encryptedFileExt
	out, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("create encrypted file: %w", err)
	}
	defer out.Close()

	writer := bufio.NewWriter(out)
	reader := bufio.NewReader(in)

	err = streamChunks(reader, fileSize, plainChunkSize, func(plain []byte) error {
		ct, err := EncryptByAes(plain, aesKey)
		if err != nil {
			return fmt.Errorf("encrypt chunk: %w", err)
		}
		_, err = writer.WriteString(ct)
		return err
	})
	if err != nil {
		return err
	}

	wrapped, err := ecies.Encrypt(publicKey, aesKey)
	if err != nil {
		return fmt.Errorf("wrap AES key: %w", err)
	}
	if _, err := writer.WriteString(hex.EncodeToString(wrapped)); err != nil {
		return fmt.Errorf("write wrapped key: %w", err)
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("flush output: %w", err)
	}

	if outInfo, err := out.Stat(); err == nil {
		fmt.Printf("File encryption successful. Encrypted file name: %s, File size: %v bytes \n",
			outPath, outInfo.Size())
	}
	return nil
}

// DecryptFile inverts EncryptFile, recovering the AES key from the file's
// hex-encoded suffix using the given ECIES private key.
func DecryptFile(filePath, privateKeyHex string) error {
	privateKey, err := ecies.NewPrivateKeyFromHex(privateKeyHex)
	if err != nil {
		return fmt.Errorf("invalid private key: %w", err)
	}

	in, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("open file: %w", err)
	}
	defer in.Close()

	info, err := in.Stat()
	if err != nil {
		return fmt.Errorf("stat file: %w", err)
	}
	fileSize := info.Size()
	fmt.Println("File size to be decrypted:", fileSize, "bytes")

	if fileSize < int64(wrappedKeyHexLen) {
		return errors.New("file is too small to contain the AES key")
	}

	aesKey, err := readWrappedKey(in, fileSize, privateKey)
	if err != nil {
		return err
	}

	outPath := decryptedPrefix + strings.TrimSuffix(filepath.Base(filePath), encryptedFileExt)
	out, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("create decrypted file: %w", err)
	}
	defer out.Close()

	if _, err := in.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("seek to start: %w", err)
	}

	writer := bufio.NewWriter(out)
	reader := bufio.NewReader(in)
	dataSize := fileSize - int64(wrappedKeyHexLen)

	err = streamChunks(reader, dataSize, encryptedChunkHexLen, func(ct []byte) error {
		plain, err := DecryptByAes(ct, aesKey)
		if err != nil {
			return fmt.Errorf("decrypt chunk: %w", err)
		}
		_, err = writer.Write(plain)
		return err
	})
	if err != nil {
		return err
	}

	if err := writer.Flush(); err != nil {
		return fmt.Errorf("flush output: %w", err)
	}

	if outInfo, err := out.Stat(); err == nil {
		fmt.Printf("File decryption successful. Decrypted file name: %s, File size: %v bytes \n",
			outInfo.Name(), outInfo.Size())
	}
	return nil
}

func readWrappedKey(f *os.File, fileSize int64, privateKey *ecies.PrivateKey) ([]byte, error) {
	keyHex := make([]byte, wrappedKeyHexLen)
	if _, err := f.ReadAt(keyHex, fileSize-int64(wrappedKeyHexLen)); err != nil {
		return nil, fmt.Errorf("read wrapped key: %w", err)
	}
	wrapped, err := hex.DecodeString(string(keyHex))
	if err != nil {
		return nil, fmt.Errorf("decode wrapped key: %w", err)
	}
	aesKey, err := ecies.Decrypt(privateKey, wrapped)
	if err != nil {
		return nil, fmt.Errorf("unwrap AES key: %w", err)
	}
	return aesKey, nil
}

// streamChunks reads exactly `total` bytes from r, calling fn on each chunk of
// up to `chunkSize`. The final chunk may be shorter when total is not a
// multiple of chunkSize.
func streamChunks(r io.Reader, total, chunkSize int64, fn func([]byte) error) error {
	if total == 0 {
		return nil
	}
	count := total / chunkSize
	if total%chunkSize != 0 {
		count++
	}
	bar := progressbar.Default(count)
	buf := make([]byte, chunkSize)
	remaining := total
	for i := int64(0); i < count; i++ {
		n := chunkSize
		if remaining < n {
			n = remaining
		}
		chunk := buf[:n]
		if _, err := io.ReadFull(r, chunk); err != nil {
			return fmt.Errorf("read chunk: %w", err)
		}
		if err := fn(chunk); err != nil {
			return err
		}
		remaining -= n
		_ = bar.Add(1)
	}
	return nil
}
