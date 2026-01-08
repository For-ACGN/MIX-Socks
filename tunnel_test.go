package msocks

import (
	"crypto/rand"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTunnel(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		server, err := listener.Accept()
		require.NoError(t, err)

		s, err := newTunnel(server, key)
		require.NoError(t, err)

		n, err := s.Write([]byte{1, 2, 3, 4})
		require.NoError(t, err)
		require.Equal(t, 4, n)

		buf := make([]byte, 8)
		n, err = io.ReadFull(s, buf)
		require.NoError(t, err)
		require.Equal(t, 8, n)
		expected := []byte{1, 2, 3, 4, 5, 6, 7, 8}
		require.Equal(t, expected, buf)

		err = s.Close()
		require.NoError(t, err)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		client, err := net.Dial("tcp", listener.Addr().String())
		require.NoError(t, err)

		c, err := newTunnel(client, key)
		require.NoError(t, err)

		buf := make([]byte, 4)
		n, err := io.ReadFull(c, buf)
		require.NoError(t, err)
		require.Equal(t, 4, n)
		expected := []byte{1, 2, 3, 4}
		require.Equal(t, expected, buf)

		n, err = c.Write([]byte{1, 2, 3, 4, 5, 6, 7, 8})
		require.NoError(t, err)
		require.Equal(t, 8, n)

		err = c.Close()
		require.NoError(t, err)
	}()

	wg.Wait()
}
