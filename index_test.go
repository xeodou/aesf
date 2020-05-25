package aesf

import (
	"bytes"
	"io"
	"testing"

	"github.com/dchest/uniuri"
)

var (
	TestPwd  = "loremlorem"
	TestText = []byte("hello world")
)

func test(pwd string, text []byte, t *testing.T) {
	testSaltSizel, _ := calSaltSize(len(pwd))
	testFullSize := len(text) + testSaltSizel + PwdVerifierSize + SignatureKeySize

	aesf, err := New(TestPwd)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	var cipher bytes.Buffer
	w, err := aesf.Encrypt(&cipher)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}
	w.Write(text)
	err = w.Close()
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	if cipher.Len() != testFullSize {
		t.Errorf("Unexpected encrypted data size %d, expect %d", cipher.Len(), testFullSize)
	}

	var plain bytes.Buffer

	dr, err := aesf.Decrypt(&cipher)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}
	_, err = io.Copy(&plain, dr)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	if err = dr.Close(); err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	if !bytes.Equal(text, plain.Bytes()) {
		t.Errorf("Unexpected decrypted data %d, expect %d", plain.Len(), len(text))
	}
}

func TestAesf(t *testing.T) {
	test(TestPwd, TestText, t)
}

func TestAESfMultipleText(t *testing.T) {
	test(TestPwd+TestPwd, []byte(uniuri.NewLen(1536)), t)
}

func TestAESfLongText(t *testing.T) {
	test(TestPwd+TestPwd, []byte(uniuri.NewLen(100536)), t)
}
