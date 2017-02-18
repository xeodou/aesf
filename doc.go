/*

AESf package combines AES encryption, sha1HMAC verification and RFC2898 key derivation,
which provide a very security way to encryp/decrypt data in golang.

Installation
	go get github.com/xeodou/aesf

Currently aesf support AES-128, AES-192, or AES-256 three types of AES encryption.

If you want know why AES CTR is a security way to encrypt data, please see the wikipedia page here,

	https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation

How do use it

```
	aesf, err := New(your_password_here)

	var cipher bytes.Buffer
	// Encrypt a Writer
	pw, err := aesf.Encrypt(&cipher)

	// Create simple Reader here
	r := strings.NewReader("some io.Reader stream to be read")

	// Write data to encrypt
	io.Copy(pw, r)

	// Close the WriteCloser
	pw.Close()
	// You will able access the cipher data from here
	// The cipher text size equal:
	// salt size + 2 bytes verifier + data size + 10 sha1HMAC size
	//

	var plain bytes.Buffer
	// Decrypt a Reader
	dr, err := aesf.Decrypt(&cipher)
	// ReadCloser try to read data
	io.Copy(&plain, dr)
	// Will do a sha1HMAC during close
	dr.Close()
	// You will be able access the plain text from here.
	// The plain text size equal:
	// data size - salt size - 2 bytes verifier - 10 sha1HMAC size

```

*/
package aesf
