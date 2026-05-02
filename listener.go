package msocks

import (
	"crypto/sha256"
	"net"

	"github.com/For-ACGN/utls"
)

type utlsListener struct {
	net.Listener
	cfg *utls.Config
}

func newUTLSListener(listener net.Listener, cfg *utls.Config, secret []byte) *utlsListener {
	cfg.OnClientHelloMessage = func(hello *utls.ClientHelloMessage) error {
		h := sha256.New()
		h.Write(hello.Random)
		h.Write(secret)
		digest := h.Sum(nil)
		if digest[0] == 0x00 && digest[1] == 0x00 && digest[2]>>4 == 0x00 {
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
