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

// 更新 文件 的加解密
const PublicKey = "024a55ffd7ccf15b215867b4a59ee8743864bffb0cb29ff833684da1f24ce5e9fe"
const PrivateKey = "a961c408cc51e0cfc676c6d40048fcb2b9e88b5fe062fb07e1868cb852c294ac" // 确保私钥不能泄露

// EncryptFile 文件加密，filePath 需要加密的文件路径 ，fName加密后文件名
func EncryptFile(filePath string) (err error) {
	f, err := os.Open(filePath)
	if err != nil {
		fmt.Println("未找到文件")
		return
	}
	defer f.Close()
	// 16,24,32位字符串的话，分别对应AES-128，AES-192，AES-256 加密方法
	PwdKey := make([]byte, 32)
	rand.Read(PwdKey)

	fInfo, _ := f.Stat()
	fLen := fInfo.Size()
	fmt.Println("待处理文件大小:", fLen, "Byte")
	maxLen := 1024 * 1024 * 100 //未加密1byte加密后为32byte
	var forNum int64 = 0
	getLen := fLen

	if fLen > int64(maxLen) {
		getLen = int64(maxLen)
		forNum = fLen / int64(maxLen)
		fmt.Println("需要解密次数：", forNum+1)
	}
	//加密后存储的文件
	ff, err := os.OpenFile(filepath.Base(filePath)+".cc", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		fmt.Println("文件写入错误")
		return err
	}
	defer ff.Close()
	buf := bufio.NewWriter(ff)
	//循环加密，并写入文件
	for i := 0; i < int(forNum+1); i++ {
		a := make([]byte, getLen)
		n, err := f.Read(a)
		if err != nil {
			fmt.Println("文件读取错误")
			return err
		}
		getByte, err := EncryptByAes(a[:n], PwdKey)
		if err != nil {
			fmt.Println("加密错误")
			return err
		}
		buf.WriteString(getByte[:])
		buf.Flush()
	}
	// AES密钥加密
	fmt.Println(hex.EncodeToString(PwdKey), "加密前的AES密钥")
	publicKey, _ := ecies.NewPublicKeyFromHex(PublicKey)
	cryptoPwdKey, _ := ecies.Encrypt(publicKey, PwdKey)
	fmt.Println(hex.EncodeToString(cryptoPwdKey), "加密后的AES密钥")
	buf.WriteString(hex.EncodeToString(cryptoPwdKey))
	buf.Flush()
	ffInfo, _ := ff.Stat()
	fmt.Printf("文件加密成功，生成文件名为：%s，文件大小为：%v Byte \n", ffInfo.Name(), ffInfo.Size())
	return nil
}

func DecryptFile(filePath string) (err error) {
	var p int64 = 258
	f, err := os.Open(filePath)
	if err != nil {
		fmt.Println("未找到文件")
		return
	}
	defer f.Close()
	fInfo, _ := f.Stat()
	fLen := fInfo.Size()
	fmt.Println("待处理文件大小:", fLen, "Byte")
	maxLen := 1024 * 1024 * 100 * 32
	var forNum int64 = 0
	getLen := fLen - p

	// 从文件末尾倒退128个字节，读取加密的AES密钥
	_, err = f.Seek(-p, os.SEEK_END)
	if err != nil {
		fmt.Println("无法将文件指针移到文件末尾：", err)
		return
	}
	// 读取128个字节的内容
	PwdKeyBytes := make([]byte, p)
	_, err = f.Read(PwdKeyBytes)
	if err != nil {
		fmt.Println("读取文件时出错：", err)
		return
	}
	// 将读取到的密钥转换为[]byte类型
	fmt.Println(string(PwdKeyBytes), "解密前的AES密钥")
	PwdKeyBytes, _ = hex.DecodeString(string(PwdKeyBytes))
	privateKey, _ := ecies.NewPrivateKeyFromHex(PrivateKey)
	PwdKey, _ := ecies.Decrypt(privateKey, PwdKeyBytes)

	fmt.Println(hex.EncodeToString(PwdKey), "解密后的AES密钥")
	if fLen > int64(maxLen) {
		getLen = int64(maxLen)
		forNum = fLen / int64(maxLen)

		fmt.Println("需要解密次数：", forNum+1)
	}

	ff, err := os.OpenFile("decryptFile_"+strings.TrimSuffix(filepath.Base(filePath), ".cc"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		fmt.Println("文件写入错误")
		return err
	}
	defer ff.Close()
	num := 0
	//循环加密，并写入文件
	// 将文件指针移到文件开始位置
	_, err = f.Seek(0, os.SEEK_SET)
	buf := bufio.NewWriter(ff)
	for i := 0; i < int(forNum+1); i++ {
		a := make([]byte, getLen)
		n, err := f.Read(a)
		if err != nil {
			fmt.Println("文件读取错误")
			return err
		}
		getByte, err := DecryptByAes(string(a[:n]), PwdKey)
		if err != nil {
			fmt.Println("解密错误")
			return err
		}

		buf.WriteString(string(getByte[:]))
		buf.Flush()
		num++
	}
	fmt.Println("解密次数：", num)
	ffInfo, _ := ff.Stat()
	fmt.Printf("文件解密成功，生成文件名为：%s，文件大小为：%v Byte \n", ffInfo.Name(), ffInfo.Size())
	return
}
