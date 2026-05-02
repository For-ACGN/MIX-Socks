package msocks

import (
	"bytes"
	"net"

	"github.com/For-ACGN/utls"
)

type utlsListener struct {
	net.Listener
	cfg *utls.Config
}

func newUTLSListener(listener net.Listener, cfg *utls.Config) *utlsListener {
	cfg.OnClientHelloMessage = func(hello *utls.ClientHelloMessage) error {
		if bytes.Equal(hello.Random, bytes.Repeat([]byte{0xFF, 0x00}, 16)) {
			hello.ALPNProto = []string{"http/1.1"}
		}
		return nil
	}
	return &utlsListener{
		Listener: listener,
		cfg:      cfg,
	}
}

func (ul *utlsListener) Accept() (net.Conn, error) {
	conn, err := ul.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return utls.Server(conn, ul.cfg), nil
}
