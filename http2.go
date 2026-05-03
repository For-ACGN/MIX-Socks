package msocks

import (
	"crypto/tls"
	"net"
)

type http2Listener struct {
	net.Listener
	config *tls.Config
}

func newHTTP2Listener(listener net.Listener, config *tls.Config) *http2Listener {
	return &http2Listener{
		Listener: listener,
		config:   config,
	}
}

func (hl *http2Listener) Accept() (net.Conn, error) {
	conn, err := hl.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &http2Conn{Conn: tls.Server(conn, hl.config)}, nil
}

type http2Conn struct {
	net.Conn
}
