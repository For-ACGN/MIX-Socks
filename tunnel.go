package msocks

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"sync"

	"github.com/pkg/errors"
)

const maxObfSize = 2048

type tunnel struct {
	net.Conn

	block cipher.Block

	key []byte
	iv  []byte
	jit int

	isHandshake  bool
	handshakeErr error
	handshakeMu  sync.Mutex

	writeCtr uint64

	writer cipher.Stream
	reader cipher.Stream

	// context data
	Protocol string
	IPType   string
	Address  string
}

func newTunnel(conn net.Conn, key []byte, jitter int) (*tunnel, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, aes.BlockSize)
	_, err = rand.Read(iv)
	if err != nil {
		return nil, err
	}
	if jitter == 0 {
		jitter = defaultJitterLevel
	}
	if jitter < 1 || jitter > maximumJitterLevel {
		return nil, errors.Errorf("jitter level must be between 1 and %d", maximumJitterLevel)
	}
	tun := tunnel{
		Conn:  conn,
		block: block,
		key:   key,
		iv:    iv,
		jit:   jitter,
	}
	return &tun, nil
}

// +----------+----------+----------+
// | obf size | obf data |  AES IV  |
// +----------+----------+----------+
// |  uint16  |   var    | 16 bytes |
// +----------+----------+----------+

func (t *tunnel) Handshake() error {
	t.handshakeMu.Lock()
	defer t.handshakeMu.Unlock()
	if t.isHandshake {
		return t.handshakeErr
	}
	t.isHandshake = true
	// generate random size data
	buf := make([]byte, 2)
	_, _ = rand.Read(buf)
	obfSize := binary.BigEndian.Uint16(buf) % maxObfSize
	obf := make([]byte, 2+obfSize)
	binary.BigEndian.PutUint16(obf[:2], obfSize)
	_, _ = rand.Read(obf[2:])
	// exchange AES IV for create read stream
	packet := append(obf, t.iv...)
	_, err := t.Conn.Write(packet)
	if err != nil {
		t.handshakeErr = errors.Wrap(err, "failed to write iv packet")
		return t.handshakeErr
	}
	// read random size data
	_, err = io.ReadFull(t.Conn, buf)
	if err != nil {
		t.handshakeErr = errors.Wrap(err, "failed to read obf size")
		return t.handshakeErr
	}
	obfSize = binary.BigEndian.Uint16(buf)
	if obfSize >= maxObfSize {
		t.handshakeErr = errors.Wrap(err, "invalid obf data size")
		return t.handshakeErr
	}
	_, err = io.CopyN(io.Discard, t.Conn, int64(obfSize))
	if err != nil {
		t.handshakeErr = errors.Wrap(err, "failed to read obf data")
		return t.handshakeErr
	}
	// read IV from remote connection
	iv := make([]byte, aes.BlockSize)
	_, err = io.ReadFull(t.Conn, iv)
	if err != nil {
		t.handshakeErr = errors.Wrap(err, "failed to read iv data")
		return t.handshakeErr
	}
	block, err := aes.NewCipher(t.key)
	if err != nil {
		t.handshakeErr = errors.Wrap(err, "failed to create reader stream")
		return t.handshakeErr
	}
	t.reader = cipher.NewCTR(block, iv)     // #nosec
	t.writer = cipher.NewCTR(t.block, t.iv) // #nosec
	// clean data after exchange
	t.key = nil
	t.iv = nil
	return nil
}

func (t *tunnel) Read(b []byte) (int, error) {
	err := t.Handshake()
	if err != nil {
		return 0, err
	}
	n, err := t.Conn.Read(b)
	if err != nil {
		return n, err
	}
	t.reader.XORKeyStream(b[:n], b[:n])
	return n, nil
}

func (t *tunnel) Write(b []byte) (int, error) {
	err := t.Handshake()
	if err != nil {
		return 0, err
	}
	if len(b) == 0 {
		return 0, nil
	}
	buf := make([]byte, len(b))
	t.writer.XORKeyStream(buf, b)
	t.writeCtr++
	if t.writeCtr < 64 {
		return t.writeSegment(buf)
	}
	if t.jit > int(buf[0]%maximumJitterLevel) {
		return t.writeSegment(buf)
	}
	return t.Conn.Write(buf)
}

func (t *tunnel) writeSegment(b []byte) (int, error) {
	mRand := newMathRand()
	numSegments := 2 + mRand.Intn(7)
	var numWritten int
	for i := 0; i < numSegments; i++ {
		if i == numSegments-1 {
			_, err := t.Conn.Write(b[numWritten:])
			if err != nil {
				return 0, err
			}
		} else {
			remaining := len(b) - numWritten
			size := mRand.Intn(len(b))
			if size > remaining {
				size = remaining
			}
			_, err := t.Conn.Write(b[numWritten : numWritten+size])
			if err != nil {
				return 0, err
			}
			numWritten += size
		}
	}
	return len(b), nil
}
