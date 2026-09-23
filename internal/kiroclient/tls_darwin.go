//go:build darwin

package kiroclient

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
)

func configureKiroTLSTransport(transport *http.Transport) {
	transport.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
		VerifyConnection:   verifyKiroTLSConnection,
	}
}

func verifyKiroTLSConnection(state tls.ConnectionState) error {
	if len(state.PeerCertificates) == 0 {
		return errors.New("kiroclient: TLS peer sent no certificates")
	}
	if state.ServerName == "" {
		return errors.New("kiroclient: TLS connection has no server name")
	}

	leaf := state.PeerCertificates[0]
	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()
	for _, certificate := range state.PeerCertificates[1:] {
		roots.AddCert(certificate)
		intermediates.AddCert(certificate)
	}
	if len(state.PeerCertificates) == 1 {
		roots.AddCert(leaf)
	}

	_, err := leaf.Verify(x509.VerifyOptions{
		DNSName:       state.ServerName,
		Intermediates: intermediates,
		Roots:         roots,
	})
	return err
}
