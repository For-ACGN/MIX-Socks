package msocks

import (
	crand "crypto/rand"
	"encoding/binary"
	"math/rand"
	"time"
)

func newMathRand() *rand.Rand {
	buf := make([]byte, 8)
	_, err := crand.Read(buf)
	if err != nil {
		now := time.Now().UnixNano()
		binary.BigEndian.PutUint64(buf, uint64(now)) // #nosec G115
	}
	seed := binary.BigEndian.Uint64(buf)
	return rand.New(rand.NewSource(int64(seed))) // #nosec
}
