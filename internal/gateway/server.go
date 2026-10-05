package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

// Certificate is the gateway's TLS certificate, from a certificate file and a key file in PEM.
// Both are checked at every handshake and read again when either changed, so a renewed certificate
// is served without a restart (SPEC.md section 13).
type Certificate struct {
	certFile, keyFile string
	log               *slog.Logger

	mu sync.Mutex
	// stamps are the files' stats when cert was read.
	stamps [2]os.FileInfo
	cert   *tls.Certificate
	// lastErr is the last problem logged, so a broken pair is logged once, not at every handshake.
	lastErr string
}

// LoadCertificate reads the certificate and key files.
func LoadCertificate(certFile, keyFile string, log *slog.Logger) (*Certificate, error) {
	c := &Certificate{certFile: certFile, keyFile: keyFile, log: log}
	stamps, err := c.stat()
	if err != nil {
		return nil, err
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("read the TLS certificate %s and key %s: %w", certFile, keyFile, err)
	}
	c.stamps, c.cert = stamps, &cert
	return c, nil
}

func (c *Certificate) stat() ([2]os.FileInfo, error) {
	var stamps [2]os.FileInfo
	for i, name := range []string{c.certFile, c.keyFile} {
		fi, err := os.Stat(name)
		if err != nil {
			return stamps, fmt.Errorf("read the TLS certificate: %w", err)
		}
		stamps[i] = fi
	}
	return stamps, nil
}

// GetCertificate returns the current certificate, read again if a file changed. A pair that cannot
// be read is logged and the previous certificate is served: a renewal written in two steps (the
// certificate, then the key) is read once both are there. The pair is tried again at every
// handshake until it reads, so a transient error does not keep the old certificate.
func (c *Certificate) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	stamps, err := c.stat()
	if err == nil && sameStamp(stamps[0], c.stamps[0]) && sameStamp(stamps[1], c.stamps[1]) {
		return c.cert, nil
	}
	var cert tls.Certificate
	if err == nil {
		cert, err = tls.LoadX509KeyPair(c.certFile, c.keyFile)
	}
	if err != nil {
		if msg := err.Error(); msg != c.lastErr {
			c.lastErr = msg
			c.log.Error("cannot read the new TLS certificate; serving the previous one", "cert", c.certFile, "key", c.keyFile, "error", err)
		}
		return c.cert, nil
	}
	c.log.Info("serving the new TLS certificate", "cert", c.certFile)
	c.stamps, c.cert, c.lastErr = stamps, &cert, ""
	return c.cert, nil
}

// Server timeouts: a client gets readHeader to send its request headers (and finish the TLS
// handshake before that), and an idle keep-alive connection is closed after idle. Requests are
// bounded by limits.request.
const (
	readHeaderTimeout = 10 * time.Second
	idleTimeout       = 2 * time.Minute
	// shutdownTimeout is how long requests in flight may finish once the gateway is told to stop.
	shutdownTimeout = 30 * time.Second
)

// Serve serves h over TLS on ln until ctx is done, then shuts down gracefully.
func Serve(ctx context.Context, ln net.Listener, h http.Handler, cert *Certificate, log *slog.Logger) error {
	srv := &http.Server{
		Handler:           h,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: cert.GetCertificate},
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ServeTLS(ln, "", "") }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	err := srv.Shutdown(sctx)
	if errors.Is(err, context.DeadlineExceeded) {
		log.Warn("requests still in flight after the shutdown timeout were cut", "timeout", shutdownTimeout)
		return srv.Close()
	}
	return err
}
