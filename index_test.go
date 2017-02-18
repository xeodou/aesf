package aesf

import (
	"bytes"
	"io"
	"testing"
)

var (
	TestPwd  = "loremlorem"
	TestText = []byte("hello world")
)

func TestAesf(t *testing.T) {
	testSaltSizel, _ := calSaltSize(len(TestPwd))
	testFullSize := len(TestText) + testSaltSizel + PwdVerifierSize + SignatureKeySize

	aesf, err := New(TestPwd)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	var cipher bytes.Buffer
	w, err := aesf.Encrypt(&cipher)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}
	w.Write(TestText)
	err = w.Close()
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	if cipher.Len() != testFullSize {
		t.Error("Unexpected encrypted data size %d, expect %d", testFullSize, cipher.Len())
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

	if !bytes.Equal(append(make([]byte, testSaltSizel+PwdVerifierSize), TestText...), plain.Bytes()) {
		t.Errorf("Unexpected decrypted data %d, expect %d", plain.Len(), len(TestText))
	}
}
