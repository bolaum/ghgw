package gateway

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeCert writes a new self-signed certificate for name and its key, and returns a pool that
// trusts it.
func writeCert(t *testing.T, certFile, keyFile, name string) *x509.CertPool {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		DNSNames:              []string{name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	// The key first: the renewal is complete once the certificate changes too.
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool
}

func newLocalListener(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

// newTLSClient returns a client that trusts only roots and expects the server to be serverName.
func newTLSClient(roots *x509.CertPool, serverName string) *http.Client {
	return &http.Client{Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: roots, ServerName: serverName},
		ForceAttemptHTTP2: true,
	}}
}

// TestServe serves the gateway on a real listener over TLS, and reloads a renewed certificate.
func TestServe(t *testing.T) {
	e := newTestEnv(t)
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	first := writeCert(t, certFile, keyFile, "first.example")
	log := slog.New(slog.NewTextHandler(e.logs, nil))
	cert, err := LoadCertificate(certFile, keyFile, log)
	if err != nil {
		t.Fatal(err)
	}
	ln := newLocalListener(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, ln, e.gw, cert, log) }()

	get := func(roots *x509.CertPool, serverName string) (*http.Response, error) {
		client := newTLSClient(roots, serverName)
		defer client.CloseIdleConnections()
		resp, err := client.Get("https://" + ln.Addr().String() + advertisement)
		if err == nil {
			resp.Body.Close()
		}
		return resp, err
	}
	resp, err := get(first, "first.example")
	if err != nil || resp.StatusCode != 401 {
		t.Fatalf("GET = %v, %v; want 401 over TLS", resp, err)
	}

	second := writeCert(t, certFile, keyFile, "second.example")
	if resp, err := get(second, "second.example"); err != nil || resp.StatusCode != 401 {
		t.Fatalf("GET after the renewal = %v, %v; want the new certificate", resp, err)
	}
	// A broken renewal keeps the certificate in use.
	if err := os.WriteFile(keyFile, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if resp, err := get(second, "second.example"); err != nil || resp.StatusCode != 401 {
		t.Fatalf("GET after a broken renewal = %v, %v; want the previous certificate", resp, err)
	}
	if !strings.Contains(e.logs.String(), "cannot read the new TLS certificate") {
		t.Errorf("logs = %s, want the broken renewal logged", e.logs.String())
	}

	cancel()
	if err := <-done; err != nil {
		t.Errorf("Serve() = %v after the context was done, want nil", err)
	}
}

func TestLoadCertificateErrors(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if _, err := LoadCertificate(certFile, keyFile, slog.Default()); err == nil || !strings.Contains(err.Error(), "read the TLS certificate") {
		t.Errorf("LoadCertificate(missing) = %v, want an error", err)
	}
	writeCert(t, certFile, keyFile, "a.example")
	if err := os.WriteFile(keyFile, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCertificate(certFile, keyFile, slog.Default()); err == nil || !strings.Contains(err.Error(), "read the TLS certificate "+certFile+" and key "+keyFile) {
		t.Errorf("LoadCertificate(bad key) = %v, want an error naming both files", err)
	}
}
