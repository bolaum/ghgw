package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// writeTestCert writes a self-signed certificate for 127.0.0.1 and its key to dir, and returns the
// files and a pool that trusts the certificate.
func writeTestCert(t *testing.T, dir string) (certFile, keyFile string, roots *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
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
	certFile, keyFile = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots = x509.NewCertPool()
	roots.AddCert(cert)
	return certFile, keyFile, roots
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// TestServe runs the admin's setup with the CLI, then serve against a fake GitHub.
func TestServe(t *testing.T) {
	stateDir := testEnv(t)
	dir := t.TempDir()
	api := fakeGitHub(t)
	mustRun(t, goodToken, "owner", "add", "bolaum", "--api-url", api, "--state-dir", stateDir)
	var k keyJSON
	if err := json.Unmarshal([]byte(mustRun(t, "", "key", "new", "--json")), &k); err != nil {
		t.Fatal(err)
	}
	policy := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policy, []byte(`
users:
  rpi01-agent:
    key_hash: `+k.KeyHash+`
    grants:
      - id: 1
        repos: ["bolaum/*"]
        access: read
`), 0o600); err != nil {
		t.Fatal(err)
	}

	var upstreamAuth string
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
		io.WriteString(w, "refs")
	}))
	t.Cleanup(upstream.Close)
	upstreamRoots := x509.NewCertPool()
	upstreamRoots.AddCert(upstream.Certificate())

	certFile, keyFile, roots := writeTestCert(t, dir)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	logs := &lockedBuffer{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- serve(ctx, serveOptions{
			certFile: certFile, keyFile: keyFile, policy: policy, stateDir: stateDir,
			gitURL: upstream.URL, rootCAs: upstreamRoots,
		}, ln, slog.New(slog.NewJSONHandler(logs, nil)))
	}()

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}
	get := func(key string) (int, string) {
		t.Helper()
		req, err := http.NewRequest("GET", "https://"+ln.Addr().String()+"/bolaum/ghgw.git/info/refs?service=git-upload-pack", nil)
		if err != nil {
			t.Fatal(err)
		}
		if key != "" {
			req.SetBasicAuth("x", key)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if status, body := get(k.Key); status != 200 || body != "refs" {
		t.Errorf("fetch with the key = %d %q, want 200 from the upstream", status, body)
	}
	if want := "Basic " + basicCredentials("x-access-token", goodToken); upstreamAuth != want {
		t.Errorf("the upstream got Authorization %q, want the owner's credential", upstreamAuth)
	}
	if status, body := get(""); status != 401 || !strings.Contains(body, "ghgw setup") {
		t.Errorf("fetch without a key = %d %q, want 401 naming ghgw setup", status, body)
	}

	cancel()
	if err := <-done; err != nil {
		t.Errorf("serve() = %v, want nil once stopped", err)
	}
	out := logs.String()
	if !strings.Contains(out, `"msg":"serving"`) || !strings.Contains(out, `"msg":"stopped"`) {
		t.Errorf("logs = %s, want serving and stopped", out)
	}
	if strings.Contains(out, k.Key) || strings.Contains(out, goodToken) {
		t.Errorf("logs = %s, hold a secret", out)
	}
}

func basicCredentials(user, password string) string {
	r := http.Request{Header: http.Header{}}
	r.SetBasicAuth(user, password)
	return strings.TrimPrefix(r.Header.Get("Authorization"), "Basic ")
}

func TestServeErrors(t *testing.T) {
	stateDir := testEnv(t)
	dir := t.TempDir()
	certFile, keyFile, _ := writeTestCert(t, dir)
	invalid := filepath.Join(dir, "invalid.yaml")
	if err := os.WriteFile(invalid, []byte("users: {a: {key_hash: x}}"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		o       serveOptions
		wantErr string
	}{
		{name: "missing certificate", o: serveOptions{certFile: filepath.Join(dir, "none.pem"), keyFile: keyFile},
			wantErr: "read the TLS certificate: stat " + filepath.Join(dir, "none.pem")},
		{name: "missing policy", o: serveOptions{certFile: certFile, keyFile: keyFile, policy: filepath.Join(dir, "none.yaml"), stateDir: stateDir},
			wantErr: "policy file " + filepath.Join(dir, "none.yaml") + " does not exist; write it (SPEC.md section 6) or point to it with --policy or $GHGW_POLICY"},
		{name: "invalid policy", o: serveOptions{certFile: certFile, keyFile: keyFile, policy: invalid, stateDir: stateDir},
			wantErr: "policy file " + invalid + " is invalid; fix it and run again:\nuser a: key_hash must be sha256:"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			tt.o.gitURL = "https://github.com"
			err = serve(context.Background(), tt.o, ln, slog.New(slog.NewTextHandler(io.Discard, nil)))
			if err == nil || !strings.HasPrefix(err.Error(), tt.wantErr) {
				t.Errorf("serve() = %v, want %q", err, tt.wantErr)
			}
			// The listener is closed: the port is free again.
			if ln2, err := net.Listen("tcp", ln.Addr().String()); err != nil {
				t.Errorf("the listener is still open: %v", err)
			} else {
				ln2.Close()
			}
		})
	}

	if _, _, err := run(t, "", "serve", "--tls-key", keyFile); err == nil || err.Error() != "serve needs --tls-cert and --tls-key: the gateway is HTTPS only (gh refuses plain HTTP)" {
		t.Errorf("serve without --tls-cert = %v", err)
	}
}
