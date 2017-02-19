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
	offsetStart  int
}

func (r *aesfReader) Read(dst []byte) (n int, err error) {
	blockSize := len(dst)
	if blockSize-r.offsetStart-SignatureKeySize <= 0 {
		return 0, io.EOF
	}
	n, err = r.r.Read(dst[r.offsetStart:])
	if n == 0 && err == nil {
		return n, io.EOF
	}

	if err != nil {
		return 0, io.ErrUnexpectedEOF
	}

	l := n - SignatureKeySize + r.offsetStart
	r.s.XORKeyStream(dst[r.offsetStart:l], dst[r.offsetStart:l])
	r.authenticate = dst[l : n+r.offsetStart]

	dst = dst[r.offsetStart:l]
	r.hash.Write(dst)
	if n+r.offsetStart < blockSize {
		return len(dst) + r.offsetStart, io.EOF
	}
	r.offsetStart = 0

	return
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
