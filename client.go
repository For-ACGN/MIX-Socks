package msocks

import (
	"bufio"
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
	"sync"
	"sync/atomic"
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

	inShutdown atomic.Bool

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
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
		ca, err := os.ReadFile(caPath) // #nosec
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

func (c *Client) shuttingDown() bool {
	return c.inShutdown.Load()
}

// Serve is used to start front server.
func (c *Client) Serve() error {
	for i := 0; i < 8; i++ {
		c.wg.Add(1)
		go c.connector()
	}
	c.logger.Infof("front server listening on %s", c.frontListener.Addr())
	var tempDelay time.Duration
	maxDelay := time.Second
	for {
		conn, err := c.frontListener.Accept()
		if err != nil {
			if c.shuttingDown() {
				return nil
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if tempDelay > maxDelay {
					tempDelay = maxDelay
				}
				c.logger.Warningf("http: Accept error: %s; retrying in %v", err, tempDelay)
				time.Sleep(tempDelay)
				continue
			}
			return err
		}
		go c.handleConn(conn)
	}
}

func (c *Client) handleConn(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	// peek first byte for switch protocol type
	reader := bufio.NewReader(conn)
	protocol, err := reader.Peek(1)
	if err != nil {
		c.logger.Warningf("failed to peek first byte: %s", err)
		return
	}
	switch protocol[0] {
	case version4:

	case version5:

	default: // HTTP tunnel or simple proxy

	}
}

func (c *Client) connector() {
	mRand := newMathRand()
	for {
		// check client is closed
		select {
		case <-c.ctx.Done():
			return
		default:
		}
		// wait random time
		var delay time.Duration
		switch mRand.Intn(10) {
		case 0, 1, 2, 3:
			delay = 0 * time.Second
		case 4:
			delay = 1 * time.Second
		case 5:
			delay = 2 * time.Second
		default:
			delay = time.Duration(mRand.Intn(250)) * time.Millisecond
		}
		// pre connect
		select {
		case <-time.After(delay):

		case <-c.ctx.Done():
			return
		}
	}
}

func (c *Client) connect() (net.Conn, error) {
	dialer := tls.Dialer{
		Config: c.tlsConfig,
	}
	conn, err := dialer.DialContext(c.ctx, c.serverNet, c.serverAddr)
	if err != nil {
		return nil, errors.Wrap(err, "failed to connect to server")
	}

	return conn, nil
}

// Close is used to close front server.
func (c *Client) Close() error {
	c.inShutdown.Store(true)
	c.logger.Info("close connectors")
	c.cancel()
	c.wg.Wait()
	var err error
	if c.frontListener != nil {
		err = c.frontListener.Close()
		if err != nil {
			err = errors.Wrap(err, "failed to close front listener")
		}
	}
	c.logger.Info("client is closed")
	_ = c.logger.Close()
	return err
}
