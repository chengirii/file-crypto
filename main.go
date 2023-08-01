package main

import aes "file-crypto/aes_file"

func main() {
	_ = aes.EncryptFile("./PomPomPurin.gif")
	_ = aes.DecryptFile("./PomPomPurin.gif.cc")
}
