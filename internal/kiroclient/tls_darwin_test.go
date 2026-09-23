//go:build darwin

package kiroclient

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"testing"
	"time"
)

func TestVerifyKiroTLSConnection_UsesPresentedChain(t *testing.T) {
	const host = "runtime.us-east-1.kiro.dev"
	root, leaf := newTestTLSChain(t, host, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))

	state := tls.ConnectionState{
		ServerName:       host,
		PeerCertificates: []*x509.Certificate{leaf, root},
	}
	if err := verifyKiroTLSConnection(state); err != nil {
		t.Fatalf("verifyKiroTLSConnection() error = %v", err)
	}
}

func TestVerifyKiroTLSConnection_RejectsWrongHost(t *testing.T) {
	root, leaf := newTestTLSChain(t, "runtime.us-east-1.kiro.dev", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))

	state := tls.ConnectionState{
		ServerName:       "wrong.example.com",
		PeerCertificates: []*x509.Certificate{leaf, root},
	}
	if err := verifyKiroTLSConnection(state); err == nil {
		t.Fatal("verifyKiroTLSConnection() succeeded for wrong host")
	}
}

func TestVerifyKiroTLSConnection_RejectsExpiredCertificate(t *testing.T) {
	const host = "runtime.us-east-1.kiro.dev"
	root, leaf := newTestTLSChain(t, host, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))

	state := tls.ConnectionState{
		ServerName:       host,
		PeerCertificates: []*x509.Certificate{leaf, root},
	}
	if err := verifyKiroTLSConnection(state); err == nil {
		t.Fatal("verifyKiroTLSConnection() succeeded for expired certificate")
	}
}

func TestNewHTTPClient_DarwinTLSVerifier(t *testing.T) {
	c := NewHTTPClient()
	transport, ok := c.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", c.httpClient.Transport)
	}
	if transport.TLSClientConfig == nil {
		t.Fatal("TLSClientConfig is nil")
	}
	if !transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify = false, want true")
	}
	if transport.TLSClientConfig.VerifyConnection == nil {
		t.Fatal("VerifyConnection is nil")
	}
}

func newTestTLSChain(t *testing.T, host string, notBefore, notAfter time.Time) (*x509.Certificate, *x509.Certificate) {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test root"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		DNSNames:     []string{host},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	return root, leaf
}
