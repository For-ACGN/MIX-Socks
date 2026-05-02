package msocks

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/For-ACGN/utls"
	"github.com/pkg/errors"
)

// parseCertificatesPEM is used to parse certificates from the PEM data.
func parseCertificatesPEM(pb []byte) ([]*x509.Certificate, error) {
	var (
		certs []*x509.Certificate
		block *pem.Block
	)
	for {
		block, pb = pem.Decode(pb)
		if block == nil {
			return nil, errors.New("invalid PEM block")
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("invalid PEM block type: %s", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
		if len(pb) == 0 {
			break
		}
	}
	return certs, nil
}

func toUTLSCertificate(cert *tls.Certificate) *utls.Certificate {
	crt := &utls.Certificate{
		Certificate:                 cert.Certificate,
		PrivateKey:                  cert.PrivateKey,
		OCSPStaple:                  cert.OCSPStaple,
		SignedCertificateTimestamps: cert.SignedCertificateTimestamps,
		Leaf:                        cert.Leaf,
	}
	for i := 0; i < len(cert.SupportedSignatureAlgorithms); i++ {
		scheme := utls.SignatureScheme(cert.SupportedSignatureAlgorithms[i])
		crt.SupportedSignatureAlgorithms[i] = scheme
	}
	return crt
}
