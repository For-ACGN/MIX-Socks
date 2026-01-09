package msocks

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/pkg/errors"
)

const (
	defaultPreConns      = 32
	defaultClientTimeout = time.Minute
)

// Client is a SoH client with SOCKS4, SOCKS5 and HTTP proxy server.
type Client struct {
	logger *logger

	passHash string
	timeout  time.Duration

	serverNet  string
	serverAddr string
	tlsConfig  *tls.Config
	client     *http.Client

	frontUsername string
	frontPassword string
	frontListener net.Listener

	connCh chan net.Conn

	ctx    context.Context
	cancel context.CancelFunc
}

// NewClient is used to create SoH client.
func NewClient(config *ClientConfig) (*Client, error) {
	logger, err := newLogger(config.Common.LogPath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to open log file")
	}
	h := sha256.Sum256([]byte(config.Common.Password))
	passHash := hex.EncodeToString(h[:])
	preConns := config.Client.PreConns
	if preConns < 1 {
		preConns = defaultPreConns
	}
	timeout := time.Duration(config.Client.Timeout)
	if timeout < time.Second {
		timeout = defaultClientTimeout
	}
	// prepare tls config for client
	tlsConfig := &tls.Config{}
	caPath := config.Server.RootCA
	if caPath != "" {
		ca, err := os.ReadFile(caPath)
		if err != nil {
			return nil, errors.Wrap(err, "failed to read Root CA certificate")
		}
		certs, err := parseCertificatesPEM(ca)
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse Root CA certificates")
		}
		certPool := x509.NewCertPool()
		for _, cert := range certs {
			certPool.AddCert(cert)
		}
		tlsConfig.RootCAs = certPool
	}
	// prepare the front server listener
	listener, err := net.Listen(config.Front.Network, config.Front.Address)
	if err != nil {
		return nil, errors.Wrap(err, "failed to listen for the front server")
	}
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		Timeout: timeout,
	}
	client := Client{
		logger:   logger,
		passHash: passHash,
		timeout:  timeout,

		serverNet:  config.Server.Network,
		serverAddr: config.Server.Address,
		tlsConfig:  tlsConfig,
		client:     httpClient,

		frontUsername: config.Front.Username,
		frontPassword: config.Front.Password,
		frontListener: listener,

		connCh: make(chan net.Conn, preConns),
	}
	client.ctx, client.cancel = context.WithCancel(context.Background())
	return &client, nil
}

// Login is used to log in to server.
func (c *Client) Login() error {
	defer c.client.CloseIdleConnections()
	resp, err := c.client.Get(fmt.Sprintf("https://%s/%s/login", c.serverAddr, c.passHash))
	if err != nil {
		return errors.Wrap(err, "failed to log in")
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return errors.Errorf("login failed with status: %s", resp.Status)
	}
	return nil
}

// Logout is used to log out to server.
func (c *Client) Logout() error {
	defer c.client.CloseIdleConnections()
	resp, err := c.client.Get(fmt.Sprintf("https://%s/%s/logout", c.serverAddr, c.passHash))
	if err != nil {
		return errors.Wrap(err, "failed to log out")
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return errors.Errorf("logout failed with status: %s", resp.Status)
	}
	return nil
}

// Serve is used to start front server.
func (c *Client) Serve() error {
	c.logger.Infof("front server listening on %s", c.frontListener.Addr())
	return nil
}

// Close is used to close front server.
func (c *Client) Close() error {
	c.logger.Info("client is closed")
	_ = c.logger.Close()
	c.cancel()
	var err error
	if c.frontListener != nil {
		err = c.frontListener.Close()
		if err != nil {
			err = errors.Wrap(err, "failed to close front listener")
		}
	}
	return err
}
