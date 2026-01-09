package msocks

import (
	"context"
	"os"
	"testing"
	"time"

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

func TestClient_Login(t *testing.T) {
	defer func() {
		testRemoveClientLogFile(t)
		testRemoveServerLogFile(t)
	}()

	serverCfg := testBuildServerConfig()
	server, err := NewServer(context.Background(), serverCfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	go func() {
		err := server.Serve()
		require.NoError(t, err)
	}()

	clientCfg := testBuildClientConfig()
	client, err := NewClient(clientCfg)
	require.NoError(t, err)
	require.NotNil(t, client)

	err = client.Login()
	require.NoError(t, err)

	err = client.Close()
	require.NoError(t, err)

	err = server.Close()
	require.NoError(t, err)
}

func TestClient_Logout(t *testing.T) {
	defer func() {
		testRemoveClientLogFile(t)
		testRemoveServerLogFile(t)
	}()

	serverCfg := testBuildServerConfig()
	server, err := NewServer(context.Background(), serverCfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	go func() {
		err := server.Serve()
		require.NoError(t, err)
	}()

	clientCfg := testBuildClientConfig()
	client, err := NewClient(clientCfg)
	require.NoError(t, err)
	require.NotNil(t, client)

	err = client.Logout()
	require.NoError(t, err)

	err = client.Close()
	require.NoError(t, err)

	err = server.Close()
	require.NoError(t, err)
}

func TestClient_Serve(t *testing.T) {
	defer func() {
		testRemoveClientLogFile(t)
		testRemoveServerLogFile(t)
	}()

	serverCfg := testBuildServerConfig()
	server, err := NewServer(context.Background(), serverCfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	go func() {
		err := server.Serve()
		require.NoError(t, err)
	}()

	clientCfg := testBuildClientConfig()
	client, err := NewClient(clientCfg)
	require.NoError(t, err)
	require.NotNil(t, client)

	go func() {
		err := client.Serve()
		require.NoError(t, err)
	}()

	time.Sleep(time.Second)

	err = client.Close()
	require.NoError(t, err)

	err = server.Close()
	require.NoError(t, err)
}
