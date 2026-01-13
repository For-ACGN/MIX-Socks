package msocks

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/For-ACGN/autocert"
	"github.com/pkg/errors"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/net/netutil"
)

// TLS mode about how to configure the certificate source.
const (
	TLSModeACME   = "acme"
	TLSModeStatic = "static"
)

const (
	defaultMaxConns      = 10000
	defaultServerTimeout = 15 * time.Second
)

// Server is a SOCKS-over-HTTPS server.
type Server struct {
	logger *logger

	passHash string

	listener net.Listener
	server   *http.Server
}

// NewServer is used to create a SoH server.
func NewServer(ctx context.Context, config *ServerConfig) (*Server, error) {
	logger, err := newLogger(config.Common.LogPath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to open log file")
	}
	passHash := config.Common.PassHash
	if passHash == "" {
		return nil, errors.New("must set password hash")
	}
	pathHash := passHash[:8] + passHash[32:32+8]
	network := config.HTTP.Network
	address := config.HTTP.Address
	var listener net.Listener
	switch config.TLS.Mode {
	case TLSModeACME:
		cfg := autocert.Config{
			Domains: config.TLS.ACME.Domains,
		}
		listener, err = autocert.ListenContext(ctx, network, address, &cfg)
		if err != nil {
			return nil, err
		}
	case TLSModeStatic:
		kp := config.TLS.Static
		cert, err := tls.LoadX509KeyPair(kp.Cert, kp.Key)
		if err != nil {
			return nil, errors.Wrap(err, "failed to load TLS certificate and key")
		}
		cfg := tls.Config{
			Certificates: []tls.Certificate{cert},
		}
		listener, err = tls.Listen(network, address, &cfg)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown TLS mode: %s", config.TLS.Mode)
	}
	// apply maximum connections
	maxConns := config.HTTP.MaxConns
	if maxConns < 1 {
		maxConns = defaultMaxConns
	}
	listener = netutil.LimitListener(listener, maxConns)
	// create http server
	timeout := time.Duration(config.HTTP.Timeout)
	if timeout < time.Second {
		timeout = defaultServerTimeout
	}
	serverMux := http.NewServeMux()
	srv := http.Server{
		ReadHeaderTimeout: timeout,
		ReadTimeout:       timeout,
		WriteTimeout:      timeout,
		Handler:           serverMux,
	}
	server := Server{
		logger:   logger,
		passHash: passHash,
		listener: listener,
		server:   &srv,
	}
	serverMux.HandleFunc("/", server.handleIndex)
	serverMux.HandleFunc(fmt.Sprintf("/%s/login", pathHash), server.handleLogin)
	serverMux.HandleFunc(fmt.Sprintf("/%s/logout", pathHash), server.handleLogout)
	serverMux.HandleFunc(fmt.Sprintf("/%s/ping", pathHash), server.handlePing)
	serverMux.HandleFunc(fmt.Sprintf("/%s/connect", pathHash), server.handleConnect)
	return &server, nil
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("hello: "))
	_, _ = w.Write([]byte(r.RemoteAddr))
	s.logger.Infof("income request: %s", r.RemoteAddr)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Pass-Hash") != s.passHash {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	garbage := make([]byte, 128+newMathRand().Intn(8*1024))
	w.Header().Set("Obfuscation", hex.EncodeToString(garbage))
	w.WriteHeader(http.StatusOK)
	s.logger.Infof("user from %s is login", r.RemoteAddr)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Pass-Hash") != s.passHash {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	garbage := make([]byte, 128+newMathRand().Intn(8*1024))
	w.Header().Set("Obfuscation", hex.EncodeToString(garbage))
	w.WriteHeader(http.StatusOK)
	s.logger.Infof("user from %s is logout", r.RemoteAddr)
}

func (s *Server) handlePing(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Pass-Hash") != s.passHash {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	garbage := make([]byte, 512+newMathRand().Intn(32*1024))
	header := w.Header()
	header.Set("Obfuscation", hex.EncodeToString(garbage))
	header.Set("Pong", "Ping-Pong")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Pass-Hash") != s.passHash {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	var success bool
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		s.logger.Errorf("connection from %s can not be hijacked", r.RemoteAddr)
		return
	}
	conn, _, err := hijacker.Hijack()
	if err != nil {
		s.logger.Error("failed to hijack connection from", r.RemoteAddr)
		return
	}
	defer func() {
		if !success {
			_ = conn.Close()
		}
	}()

	// negotiate session key
	sessionKey, serverPub, err := s.negotiate(r)
	if err != nil {
		return
	}
	header := make(http.Header)
	header.Set("Public-Key", hex.EncodeToString(serverPub))

	// append garbage data
	garbage := make([]byte, 256+newMathRand().Intn(16*1024))
	header.Set("Obfuscation", hex.EncodeToString(garbage))

	// try to connect target
	var connectOK bool
	network := r.Header.Get("Network")
	address := r.Header.Get("Address")
	target, err := net.Dial(network, address)
	if err != nil {
		header.Set("Connect-Error", err.Error())
	} else {
		defer func() {
			if !success {
				_ = target.Close()
			}
		}()
		connectOK = true
	}

	// write response
	resp := http.Response{}
	resp.StatusCode = http.StatusOK
	resp.Proto = "HTTP/1.1"
	resp.ProtoMajor = 1
	resp.ProtoMinor = 1
	resp.Header = header
	err = resp.Write(conn)
	if err != nil {
		s.logger.Errorf("failed to write response to %s: %s", r.RemoteAddr, err)
		return
	}
	if !connectOK {
		return
	}

	// clear deadline that server set
	_ = conn.SetDeadline(time.Time{})

	// start forward connection data
	tun, err := newTunnel(conn, sessionKey)
	if err != nil {
		s.logger.Error("failed to create tunnel:", err)
		return
	}
	go func() {
		defer func() { _ = target.Close() }()
		_, _ = io.Copy(target, tun)
	}()
	go func() {
		defer func() { _ = tun.Close() }()
		_, _ = io.Copy(tun, target)
	}()
	success = true
}

func (s *Server) negotiate(r *http.Request) ([]byte, []byte, error) {
	// get public key from client
	clientPub, err := hex.DecodeString(r.Header.Get("Public-Key"))
	if err != nil {
		s.logger.Error("failed to decode public key from:", r.RemoteAddr)
		return nil, nil, err
	}
	if len(clientPub) != curve25519.ScalarSize {
		s.logger.Error("receive invalid public key from:", r.RemoteAddr)
		return nil, nil, err
	}
	// process key exchange
	serverPri := make([]byte, curve25519.ScalarSize)
	_, err = rand.Read(serverPri)
	if err != nil {
		s.logger.Error("failed to generate random data for key exchange:", err)
		return nil, nil, err
	}
	serverPub, err := curve25519.X25519(serverPri, curve25519.Basepoint)
	if err != nil {
		s.logger.Errorf("failed to x25519 with base point: %s, from: %s", err, r.RemoteAddr)
		return nil, nil, err
	}
	sessionKey, err := curve25519.X25519(serverPri, clientPub)
	if err != nil {
		s.logger.Errorf("failed to negotiate session key: %s, from: %s", err, r.RemoteAddr)
		return nil, nil, err
	}
	return sessionKey, serverPub, nil
}

// Serve is used to start http server.
func (s *Server) Serve() error {
	s.logger.Infof("server listening on %s", s.listener.Addr())
	err := s.server.Serve(s.listener)
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	return err
}

// Close is used to close http server.
func (s *Server) Close() error {
	err := s.server.Close()
	_ = s.listener.Close()
	s.logger.Info("server is closed")
	_ = s.logger.Close()
	return err
}
