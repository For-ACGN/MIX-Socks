package msocks

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"net"
	"sync"

	"github.com/pkg/errors"
)

type tunnel struct {
	net.Conn

	key []byte
	iv  []byte

	isHandshake  bool
	handshakeErr error
	handshakeMu  sync.Mutex

	writer cipher.Stream
	reader cipher.Stream
}

func newTunnel(conn net.Conn, key []byte) (*tunnel, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, aes.BlockSize)
	_, err = rand.Read(iv)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(block, iv)
	t := tunnel{
		Conn:   conn,
		key:    key,
		iv:     iv,
		writer: stream,
	}
	return &t, nil
}

// +----------+----------+----------+
// | obf size | obf data |  AES IV  |
// +----------+----------+----------+
// |   byte   |   var    | 16 bytes |
// +----------+----------+----------+

func (t *tunnel) Handshake() error {
	t.handshakeMu.Lock()
	defer t.handshakeMu.Unlock()
	if t.isHandshake {
		return t.handshakeErr
	}
	t.isHandshake = true
	// generate random size data
	obfSize := make([]byte, 1)
	_, _ = rand.Read(obfSize)
	obf := make([]byte, 1+obfSize[0])
	obf[0] = obfSize[0]
	_, _ = rand.Read(obf[1:])
	// exchange AES IV for create read stream
	packet := append(obf, t.iv...)
	_, err := t.Conn.Write(packet)
	if err != nil {
		t.handshakeErr = errors.Wrap(err, "failed to write iv packet")
		return t.handshakeErr
	}
	// read IV from remote connection
	_, err = io.ReadFull(t.Conn, obfSize)
	if err != nil {
		t.handshakeErr = errors.Wrap(err, "failed to read obf size")
		return t.handshakeErr
	}
	_, err = io.CopyN(io.Discard, t.Conn, int64(obfSize[0]))
	if err != nil {
		t.handshakeErr = errors.Wrap(err, "failed to read obf data")
		return t.handshakeErr
	}
	iv := make([]byte, aes.BlockSize)
	_, err = t.Conn.Read(iv)
	if err != nil {
		t.handshakeErr = errors.Wrap(err, "failed to read iv data")
		return t.handshakeErr
	}
	block, err := aes.NewCipher(t.key)
	if err != nil {
		t.handshakeErr = errors.Wrap(err, "failed to create reader stream")
		return t.handshakeErr
	}
	t.reader = cipher.NewCTR(block, iv)
	// clean data after exchange
	_, _ = rand.Read(t.key)
	_, _ = rand.Read(t.iv)
	return nil
}
