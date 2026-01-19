package msocks

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const testServerLogFile = "testdata/server.log"

func testRemoveServerLogFile(t *testing.T) {
	err := os.Remove(testServerLogFile)
	require.NoError(t, err)
}

func testBuildServerConfig() *ServerConfig {
	config := ServerConfig{}
	config.Common.LogPath = testServerLogFile
	config.Common.PassHash = testPassHash
	config.HTTP.Network = "tcp"
	config.HTTP.Address = "127.0.0.1:2019"
	config.TLS.Mode = TLSModeStatic
	config.TLS.Static.Cert = "testdata/server_cert.pem"
	config.TLS.Static.Key = "testdata/server_key.pem"
	config.Web.Directory = "cmd/server/web"
	return &config
}

func TestNewServer(t *testing.T) {
	defer testRemoveServerLogFile(t)

	config := testBuildServerConfig()
	server, err := NewServer(context.Background(), config)
	require.NoError(t, err)
	require.NotNil(t, server)

	err = server.Close()
	require.NoError(t, err)
}

func TestServer_Serve(t *testing.T) {
	defer testRemoveServerLogFile(t)

	config := testBuildServerConfig()
	server, err := NewServer(context.Background(), config)
	require.NoError(t, err)
	require.NotNil(t, server)

	go func() {
		err := server.Serve()
		require.NoError(t, err)
	}()

	time.Sleep(time.Second)

	err = server.Close()
	require.NoError(t, err)
}
