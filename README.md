# File-Crypto

基于 AES + ECIES 的混合加密文件工具。明文按块用 AES-256-CBC 加密，AES 密钥本身用 ECIES（椭圆曲线集成加密方案）的公钥加密后追加在密文文件末尾，解密端用对应私钥还原 AES 密钥再解密文件。

![PomPomPurin](./PomPomPurin.gif)

## 特性

- **混合加密**：对称（AES-256-CBC）加密大文件内容，非对称（ECIES / secp256k1）保护对称密钥。
- **流式分块**：按 10MB 分块读写，支持任意大小的文件，不会将整个文件载入内存。
- **进度展示**：使用 `progressbar` 实时显示加/解密进度。
- **单文件输出**：加密结果写入 `<原文件名>.cc`，AES 密钥的 ECIES 密文以十六进制追加在文件尾部，解密时无需额外配套文件。

## 工作流程

```
明文文件 ──分块 10MB──┐
                      ▼
              AES-256-CBC 加密 (PKCS7 填充)
                      ▼
                  hex 编码
                      ▼
        ┌─────────────┴─────────────┐
        │ 块1 hex │ 块2 hex │ ... │ 块N hex │ ECIES(AES_key) hex (258 字节) │
        └───────────────────────────┘
                  └──> 输出 <原文件名>.cc
```

解密时反向：从文件尾部读取固定长度（258 字节）的 ECIES 密文，用私钥解出 AES 密钥；再倒回文件头按块解密前面的内容。

## 安装

需要 Go 1.21+。

```bash
git clone https://github.com/chengirii/file-crypto.git
cd file-crypto
go build ./...
```

## 使用

### 1. 生成 ECIES 密钥对

`aes_file/ecies_test.go` 提供了密钥生成测试：

```bash
go test -run TestGenerateEciesKey -v ./aes_file/
```

输出示例：

```
PublicKey: 03350c307b4771243cd40184bb9120404c96119033998ea147944b85d3e17f2c6a
PrivateKey: 6e7486d1ceb447c3c63cba76268e3b6b072b861abaa59fe84df49da7ed74b71f
```

公钥用于加密端，私钥用于解密端。**私钥必须妥善保管**——丢失意味着文件无法恢复。

### 2. 加/解密

修改 `main.go` 中的文件路径与密钥：

```go
package main

import (
    aes "file-crypto/aes_file"
    "log"
)

func main() {
    if err := aes.EncryptFile("./pe.iso", "<public-key-hex>"); err != nil {
        log.Println(err)
    }
    if err := aes.DecryptFile("./pe.iso.cc", "<private-key-hex>"); err != nil {
        log.Println(err)
    }
}
```

运行：

```bash
go run .
```

输出文件：

| 操作 | 输入 | 输出 |
| ---- | ---- | ---- |
| 加密 | `pe.iso` | `pe.iso.cc` |
| 解密 | `pe.iso.cc` | `decrypted_pe.iso` |

## API

```go
// EncryptFile 用 publicKeyHex（ECIES 压缩公钥 hex）加密 filePath，输出 <basename>.cc。
func EncryptFile(filePath, publicKeyHex string) error

// DecryptFile 用 privateKeyHex（ECIES 私钥 hex）解密 filePath（应以 .cc 结尾），
// 输出 decrypted_<basename>。
func DecryptFile(filePath, privateKeyHex string) error
```

## 项目结构

```
.
├── main.go                       # 示例入口
└── aes_file/
    ├── aes.go                    # AES-256-CBC + PKCS7 + hex 编解码
    ├── crypto_file.go            # 文件级加/解密、ECIES 密钥包装
    ├── ecies_test.go             # ECIES 密钥生成与单条消息加解密示例
    └── rsa_test.go               # 备用：RSA 密钥对生成与加解密示例
```

## 实现细节

| 项目 | 取值 |
| ---- | ---- |
| 对称算法 | AES-256-CBC |
| 填充 | PKCS7 |
| 分块大小 | 10 MiB（明文） |
| 块编码 | hex |
| 非对称算法 | ECIES over secp256k1（[`ecies/go/v2`](https://github.com/ecies/go)） |
| 包装密钥长度 | 129 字节（hex 编码后 258 字节）追加在文件尾部 |

## 安全注意事项

- **IV 复用**：当前实现复用 AES 密钥的前 16 字节作为 CBC 的 IV。由于每次加密都生成新的随机 AES 密钥，不会在不同文件之间复用同一对 (key, IV)，但块之间使用相同 IV 仍是 CBC 模式下的弱点。如需更高安全性，应改为每块使用随机 IV 并将其前置写入。
- **完整性**：CBC 不提供认证，密文被篡改不会被检测。生产环境建议改用 AES-GCM 或在文件级追加 HMAC。
- **私钥管理**：私钥需离线安全保存；任何持有私钥者都可解密所有用对应公钥加密过的文件。

## 许可证

参见仓库根目录。
