package msocks

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/pelletier/go-toml/v2"
	"github.com/stretchr/testify/require"
)

var testPassHash string

func init() {
	h := sha256.Sum256([]byte("test"))
	testPassHash = hex.EncodeToString(h[:])
	fmt.Println("pass hash:", testPassHash)
}

type testDuration struct {
	Timeout duration `toml:"timeout"`
}

func TestDuration_MarshalText(t *testing.T) {
	d := testDuration{Timeout: duration(time.Second)}

	data, err := toml.Marshal(d)
	require.NoError(t, err)

	expected := "timeout = '1s'\n"
	require.Equal(t, expected, string(data))
}

func TestDuration_UnmarshalText(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		data := []byte("timeout = \"1s\"\n")

		var d testDuration
		err := toml.Unmarshal(data, &d)
		require.NoError(t, err)

		require.Equal(t, time.Second, time.Duration(d.Timeout))
	})

	t.Run("failed to parse duration", func(t *testing.T) {
		data := []byte("timeout = \"1as\"\n")

		var d testDuration
		err := toml.Unmarshal(data, &d)
		require.EqualError(t, err, "toml: time: unknown unit \"as\" in duration \"1as\"")
	})
}
