package msocks

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/pkg/errors"
)

const (
	maxObfDataSize = 2048
	minSegmentSize = 64
)

type tunnel struct {
	net.Conn

	mRand *mathRand
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
	Elapsed  time.Duration
	Protocol string
	IPType   string
	Address  string

	mu sync.Mutex
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
		mRand: newMathRand(),
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
	obfSize := binary.BigEndian.Uint16(buf) % maxObfDataSize
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
	if obfSize >= maxObfDataSize {
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
	if len(b) == 0 {
		return 0, nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
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
	t.mu.Lock()
	defer t.mu.Unlock()
	buf := make([]byte, len(b)) // TODO use sync.Pool
	t.writer.XORKeyStream(buf, b)
	t.writeCtr++
	if t.writeCtr < uint64(16+t.mRand.Intn(32)) {
		return t.writeSegment(buf)
	}
	if t.jit > int(buf[0]%maximumJitterLevel) {
		return t.writeSegment(buf)
	}
	return t.Conn.Write(buf)
}

func (t *tunnel) writeSegment(b []byte) (int, error) {
	total := len(b)
	if total <= minSegmentSize {
		return t.Conn.Write(b)
	}
	numSeg := 2 + t.mRand.Intn(t.jit*(total/1024))

	// generate split points
	points := make([]int, numSeg-1)
	for i := range points {
		points[i] = t.mRand.Intn(total)
	}
	sort.Ints(points)

	// calculate the segment size
	sizes := make([]int, numSeg)
	prev := 0
	for i, p := range points {
		sizes[i] = p - prev
		prev = p
	}
	sizes[numSeg-1] = total - prev
	t.mRand.Shuffle(len(sizes), func(i, j int) {
		sizes[i], sizes[j] = sizes[j], sizes[i]
	})

	// merge the too small segment into the previous one
	merged := make([]int, 0, len(sizes))
	for _, size := range sizes {
		if len(merged) > 0 && size < minSegmentSize {
			merged[len(merged)-1] += size
		} else {
			merged = append(merged, size)
		}
	}

	// write segments
	offset := 0
	for _, size := range merged {
		_, err := t.Conn.Write(b[offset : offset+size])
		if err != nil {
			return 0, err
		}
		offset += size
	}
	return total, nil
}
