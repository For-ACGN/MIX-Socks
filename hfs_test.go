package msocks

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHFS(t *testing.T) {
	defer testRemoveServerLogFile(t)

	config := testBuildServerConfig()
	server, err := NewServer(context.Background(), config)
	require.NoError(t, err)
	require.NotNil(t, server)

	go func() {
		err := server.Serve()
		require.NoError(t, err)
	}()

	cfg := testBuildClientConfig()
	certs, err := parseCertificatesPEM([]byte(cfg.Server.RootCA))
	require.NoError(t, err)
	tlsConfig := &tls.Config{}
	tlsConfig.RootCAs = x509.NewCertPool()
	tlsConfig.RootCAs.AddCert(certs[0])
	tr := http.Transport{
		TLSClientConfig: tlsConfig,
	}
	client := http.Client{
		Transport: &tr,
	}

	t.Run("common", func(t *testing.T) {
		URL := "https://127.0.0.1:2019/"
		req, err := http.NewRequest(http.MethodGet, URL, nil)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)

		data, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equal(t, []byte("Hello World!"), data)
	})

	err = server.Close()
	require.NoError(t, err)
}
