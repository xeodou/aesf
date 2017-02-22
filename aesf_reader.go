package aesf

import (
	"bytes"
	"crypto/cipher"
	"hash"
	"io"
	"strconv"
)

type ReaderSizeError int

func (r ReaderSizeError) Error() string {
	return "asef: invalid block size " + strconv.Itoa(int(r))
}

type aesfReader struct {
	s            cipher.Stream
	r            io.Reader
	hash         hash.Hash
	authenticate []byte
}

func (r *aesfReader) Read(block []byte) (n int, err error) {
	blockSize := len(block)
	if blockSize-SignatureKeySize <= 0 {
		return 0, io.EOF
	}
	n, err = r.r.Read(block)
	if n == 0 || err == io.EOF {
		return n, io.EOF
	}

	if err != nil {
		return 0, io.ErrUnexpectedEOF
	}
	p := n - SignatureKeySize + len(r.authenticate)

	cipher := make([]byte, 0)
	cipher = append(cipher, r.authenticate...)
	cipher = append(cipher, block...)

	r.s.XORKeyStream(block[:p], cipher[:p])
	r.hash.Write(block[:p])
	r.authenticate = cipher[p : p+SignatureKeySize]

	if n < blockSize {
		return p, io.EOF
	}

	return p, nil
}

func (r *aesfReader) Close() error {
	if !bytes.Equal(r.hash.Sum(nil)[:SignatureKeySize], r.authenticate) {
		return ErrSignatureFail
	}

	if c, ok := r.r.(io.Closer); ok {
		return c.Close()
	}
	return nil
}
