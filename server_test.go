package msocks

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

const testServerLogFile = "testdata/server.log"

func testRemoveServerLogFile(t *testing.T) {
	err := os.Remove(testServerLogFile)
	require.NoError(t, err)
}

func TestNewServer(t *testing.T) {
	defer testRemoveServerLogFile(t)

	config := ServerConfig{}
	config.Common.LogPath = testServerLogFile
	config.Common.PassHash = testPassHash
	config.HTTP.Network = "tcp"
	config.HTTP.Address = "127.0.0.1:2019"
	config.TLS.Mode = TLSModeStatic
	config.TLS.Static.Cert = "testdata/server_cert.pem"
	config.TLS.Static.Key = "testdata/server_key.pem"

	server, err := NewServer(context.Background(), &config)
	require.NoError(t, err)
	require.NotNil(t, server)

	err = server.Close()
	require.NoError(t, err)
}
