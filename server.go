package msocks

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
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
	defaultMaxConns = 1000
	defaultTimeout  = time.Minute
)

// Server is a SOCKS-over-HTTPS server.
type Server struct {
	logger *logger

	listener net.Listener
	server   *http.Server
}

// NewServer is used to create a SoH server.
func NewServer(ctx context.Context, config *ServerConfig) (*Server, error) {
	logger, err := newLogger(config.Common.LogPath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to open log file")
	}
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
	serverMux := http.NewServeMux()
	timeout := time.Duration(config.HTTP.Timeout)
	if timeout < time.Second {
		timeout = defaultTimeout
	}
	srv := http.Server{
		ReadHeaderTimeout: timeout,
		ReadTimeout:       timeout,
		WriteTimeout:      timeout,
		IdleTimeout:       timeout,
		Handler:           serverMux,
	}
	server := Server{
		logger:   logger,
		listener: listener,
		server:   &srv,
	}
	hash := config.Common.PassHash
	serverMux.HandleFunc("/", server.handleIndex)
	serverMux.HandleFunc(fmt.Sprintf("/%s/login", hash), server.handleLogin)
	serverMux.HandleFunc(fmt.Sprintf("/%s/logout", hash), server.handleLogout)
	serverMux.HandleFunc(fmt.Sprintf("/%s/connect", hash), server.handleConn)
	return &server, nil
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("hello: "))
	_, _ = w.Write([]byte(r.RemoteAddr))
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	s.logger.Infof("user from %s is login", r.RemoteAddr)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	s.logger.Infof("user from %s is logout", r.RemoteAddr)
}

func (s *Server) handleConn(w http.ResponseWriter, r *http.Request) {
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
	defer func() { _ = conn.Close() }()

	// negotiate session key
	sessionKey, serverPub, err := s.negotiate(r)
	if err != nil {
		return
	}
	header := make(http.Header)
	header.Set("Public-Key", hex.EncodeToString(serverPub))

	// append garbage data
	buf := make([]byte, 4)
	_, _ = rand.Read(buf)
	size := binary.BigEndian.Uint32(buf) % 512
	garbage := make([]byte, size)
	header.Set("Obfuscation", hex.EncodeToString(garbage))

	// try to connect target
	var success bool
	network := r.Header.Get("Network")
	address := r.Header.Get("Address")
	target, err := net.Dial(network, address)
	if err != nil {
		header.Set("Connect-Error", err.Error())
	} else {
		success = true
	}

	// write response
	resp := http.Response{}
	resp.Status = "200 OK"
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
	if !success {
		return
	}

	// start forward connection

	// clear deadline that server set
	_ = conn.SetDeadline(time.Time{})

	_ = target.Close()
	_ = sessionKey
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
		s.logger.Errorf("failed to generate random data for key exchange: %s", err)
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
	return s.server.Serve(s.listener)
}

// Close is used to close http server.
func (s *Server) Close() error {
	err := s.logger.Close()
	e := s.server.Close()
	if e != nil && err == nil {
		err = e
	}
	return err
}
