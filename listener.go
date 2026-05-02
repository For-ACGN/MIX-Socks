package msocks

import (
	"bytes"
	"crypto/tls"
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

func ToTLSCertificate(cert *utls.Certificate) *tls.Certificate {
	c := &tls.Certificate{
		Certificate:                 cert.Certificate,
		PrivateKey:                  cert.PrivateKey,
		OCSPStaple:                  cert.OCSPStaple,
		SignedCertificateTimestamps: cert.SignedCertificateTimestamps,
		Leaf:                        cert.Leaf,
	}
	for i := 0; i < len(cert.SupportedSignatureAlgorithms); i++ {
		c.SupportedSignatureAlgorithms[i] = tls.SignatureScheme(cert.SupportedSignatureAlgorithms[i])
	}
	return c
}

func ToUTLSCertificate(cert *tls.Certificate) *utls.Certificate {
	c := &utls.Certificate{
		Certificate:                 cert.Certificate,
		PrivateKey:                  cert.PrivateKey,
		OCSPStaple:                  cert.OCSPStaple,
		SignedCertificateTimestamps: cert.SignedCertificateTimestamps,
		Leaf:                        cert.Leaf,
	}
	for i := 0; i < len(cert.SupportedSignatureAlgorithms); i++ {
		c.SupportedSignatureAlgorithms[i] = utls.SignatureScheme(cert.SupportedSignatureAlgorithms[i])
	}
	return c
}
