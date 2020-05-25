package aesf

import (
	"bytes"
	"errors"
	"io"
	"strconv"

	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"

	"github.com/dchest/uniuri"
	"golang.org/x/crypto/pbkdf2"
)

const (
	// Default iterations of derivation key producing
	DefaultIterations = 4096
	// Authentication field size
	SignatureKeySize = 10
	// Password verifier size
	PwdVerifierSize = 2
)

var (
	// Invalid decrypt key
	ErrBadPassword = errors.New("asef: invalid password")
	// Envalid data signature
	ErrSignatureFail = errors.New("asef: invalid signature key")
)

// Encrypt key size should be between 8 bytes to 64 bytes.
type PasswordSizeError int

func (p PasswordSizeError) Error() string {
	return "asef: invalid key size " + strconv.Itoa(int(p))
}

func calSaltSize(pwdSize int) (int, error) {
	switch {
	case pwdSize >= 8 && pwdSize < 32:
		return 8, nil
	case pwdSize >= 32 && pwdSize < 48:
		return 12, nil
	case pwdSize >= 48 && pwdSize < 64:
		return 16, nil
	}
	return 0, PasswordSizeError(pwdSize)
}

type AESf struct {
	password                string
	iter, saltSize, keySize int
}

func New(password string) (*AESf, error) {
	saltSize, err := calSaltSize(len(password))
	if err != nil {
		return &AESf{}, err
	}

	return &AESf{
		password: password,
		iter:     DefaultIterations,
		saltSize: saltSize,
		keySize:  saltSize * 2,
	}, nil
}

func (aesf *AESf) pbkdf2Key(salt []byte) []byte {
	return pbkdf2.Key([]byte(aesf.password), salt, aesf.iter, aesf.keySize*2+PwdVerifierSize, sha256.New)
}

func (aesf *AESf) Encrypt(ciphertext io.Writer) (plaintext io.WriteCloser, err error) {

	salt := []byte(uniuri.NewLen(aesf.saltSize))
	dk := aesf.pbkdf2Key(salt)

	block, err := aes.NewCipher(dk[:aesf.keySize])
	if err != nil {
		return
	}
	stream := cipher.NewCTR(block, dk[aesf.keySize:aesf.keySize*2])
	sha1Mac := hmac.New(sha256.New, dk[aesf.keySize:aesf.keySize*2])

	_, err = ciphertext.Write(append(salt, dk[aesf.keySize*2:]...))
	if err != nil {
		return
	}
	plaintext = &aesfWriter{s: stream, w: ciphertext, hash: sha1Mac}

	return
}

func (aesf *AESf) Decrypt(ciphertext io.Reader) (plaintext io.ReadCloser, err error) {
	header := make([]byte, aesf.saltSize+PwdVerifierSize)
	lr := io.LimitReader(ciphertext, int64(len(header)))
	if _, err = lr.Read(header); err != nil {
		return
	}

	dk := aesf.pbkdf2Key(header[:aesf.saltSize])
	if !bytes.Equal(header[aesf.saltSize:], dk[aesf.keySize*2:]) {
		return nil, ErrBadPassword
	}

	block, err := aes.NewCipher(dk[:aesf.keySize])
	if err != nil {
		return
	}
	stream := cipher.NewCTR(block, dk[aesf.keySize:aesf.keySize*2])
	sha1Mac := hmac.New(sha256.New, dk[aesf.keySize:aesf.keySize*2])

	plaintext = &aesfReader{
		s:    stream,
		r:    ciphertext,
		hash: sha1Mac,
	}

	return
}
