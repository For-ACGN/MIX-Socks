package msocks

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"github.com/For-ACGN/autocert"
)

const (
	TLSModeACME   = "acme"
	TLSModeStatic = "static"
)

// Server is a SOCKS-over-HTTPS server.
type Server struct {
	passHash string
	logger   *logger
}

// NewServer is used to create a SoH server.
func NewServer(ctx context.Context, config *ServerConfig) (*Server, error) {
	logger, err := newLogger(config.Common.LogPath)
	if err != nil {
		return nil, err
	}

	maxConns := config.HTTP.MaxConns
	if maxConns < 1 {
		maxConns = 1000
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
		cfg := tls.Config{}
		listener, err = tls.Listen(network, address, &cfg)
	default:
		return nil, fmt.Errorf("unknown TLS mode: %s", config.TLS.Mode)
	}
	if err != nil {
		return nil, err
	}

	server := Server{
		logger: logger,
	}
	return &server, nil
}
