package msocks

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

const testClientLogFile = "testdata/client.log"

var (
	testProxyUsername = "proxy_user"
	testProxyPassword = "proxy_pass"
)

func testRemoveClientLogFile(t *testing.T) {
	err := os.Remove(testClientLogFile)
	require.NoError(t, err)
}

func testBuildClientConfig() *ClientConfig {
	config := ClientConfig{}
	config.Common.LogPath = testClientLogFile
	config.Common.Password = testPassword
	config.Server.Network = "tcp"
	config.Server.Address = "127.0.0.1:2019"
	config.Server.RootCA = "testdata/root_ca.pem"
	config.Front.Network = "tcp"
	config.Front.Address = "127.0.0.1:2020"
	config.Front.Username = testProxyUsername
	config.Front.Password = testProxyPassword
	return &config
}

func TestNewClient(t *testing.T) {
	defer testRemoveClientLogFile(t)

	config := testBuildClientConfig()
	client, err := NewClient(config)
	require.NoError(t, err)
	require.NotNil(t, client)

	err = client.Close()
	require.NoError(t, err)
}
