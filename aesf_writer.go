package aesf

import (
	"crypto/cipher"
	"hash"
	"io"
)

type aesfWriter struct {
	s    cipher.Stream
	w    io.Writer
	hash hash.Hash
}

func (w *aesfWriter) Write(src []byte) (n int, err error) {
	c := make([]byte, len(src))
	w.s.XORKeyStream(c, src)
	n, err = w.w.Write(c)
	if n != len(src) {
		if err == nil {
			err = io.ErrShortWrite
		}
	}
	w.hash.Write(src)
	return
}

func (w *aesfWriter) Close() error {
	_, err := w.w.Write(w.hash.Sum(nil)[:SignatureKeySize])
	if err != nil {
		return err
	}
	if c, ok := w.w.(io.Closer); ok {
		return c.Close()
	}
	return nil
}
