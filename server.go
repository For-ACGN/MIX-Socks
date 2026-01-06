package msocks

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/For-ACGN/autocert"
	"github.com/pkg/errors"
	"golang.org/x/net/netutil"
)

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
	default:
		return nil, fmt.Errorf("unknown TLS mode: %s", config.TLS.Mode)
	}
	if err != nil {
		return nil, err
	}
	// apply maximum connections
	maxConns := config.HTTP.MaxConns
	if maxConns < 1 {
		maxConns = defaultMaxConns
	}
	listener = netutil.LimitListener(listener, maxConns)
	// create http server
	mux := http.NewServeMux()
	timeout := time.Duration(config.HTTP.Timeout)
	if timeout < time.Second {
		timeout = defaultTimeout
	}
	srv := http.Server{
		ReadHeaderTimeout: timeout,
		ReadTimeout:       timeout,
		WriteTimeout:      timeout,
		IdleTimeout:       timeout,
		Handler:           mux,
	}
	server := Server{
		logger:   logger,
		listener: listener,
		server:   &srv,
	}
	mux.HandleFunc("/", server.handleIndex)
	mux.HandleFunc("/"+config.Common.PassHash, server.handleConn)
	return &server, nil
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("hello: "))
	_, _ = w.Write([]byte(r.RemoteAddr))
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
