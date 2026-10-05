// Package gateway is the gateway listener (SPEC.md section 5): it authenticates every request with
// a ghgw key, decides it with core and forwards what the policy allows to GitHub with the owner's
// credential. It holds no policy of its own; transports stay thin.
package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/bolaum/ghgw/internal/store"
)

// DefaultGitURL is where git is served on GitHub.
const DefaultGitURL = "https://github.com"

// Config configures a Gateway.
type Config struct {
	// PolicyPath is the policy file (SPEC.md section 6). It is read again when it changes.
	PolicyPath string
	// Store holds the owners and their credentials.
	Store *store.Store
	// GitURL is the base URL git requests are forwarded to: DefaultGitURL, or a fake GitHub in
	// tests. It must be https: the owner's credential travels with every request.
	GitURL string
	// RootCAs verifies the upstream's certificate; nil means the system roots.
	RootCAs *x509.CertPool
	Logger  *slog.Logger
}

// limits bound what one request can cost, whatever the client or the upstream does.
type limits struct {
	// answer bounds a request that is not forwarded, reading what is left of its body included:
	// an unauthenticated or denied client cannot hold a connection.
	answer time.Duration
	// request bounds a forwarded request, reading its body and writing the answer included: a
	// clone of a large repository fits, a stalled client or upstream does not hold a connection
	// for ever.
	request time.Duration
	// uploadPackBody bounds the body of a fetch negotiation (wants and haves). Real ones are far
	// smaller, even for repositories with many refs.
	uploadPackBody int64
	// dial, tlsHandshake and responseHeader bound the upstream's steps before the body.
	dial, tlsHandshake, responseHeader time.Duration
}

var defaultLimits = limits{
	answer:         30 * time.Second,
	request:        30 * time.Minute,
	uploadPackBody: 64 << 20,
	dial:           10 * time.Second,
	tlsHandshake:   10 * time.Second,
	responseHeader: 2 * time.Minute,
}

// maxHeaderBytes bounds the header block of a request and of an upstream answer.
const maxHeaderBytes = 64 << 10

// Gateway is the handler of the gateway listener. It is safe for concurrent use.
type Gateway struct {
	policy    *policySource
	store     *store.Store
	gitURL    *url.URL
	transport *http.Transport
	log       *slog.Logger
	limits    limits
}

// New returns the gateway for cfg. It reads the policy file once, so a gateway with an invalid
// policy never starts.
func New(ctx context.Context, cfg Config) (*Gateway, error) {
	gitURL, err := parseUpstream(cfg.GitURL)
	if err != nil {
		return nil, err
	}
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	g := &Gateway{
		policy: &policySource{path: cfg.PolicyPath, store: cfg.Store, log: log},
		store:  cfg.Store,
		gitURL: gitURL,
		log:    log,
		limits: defaultLimits,
	}
	g.transport = newTransport(cfg.RootCAs, g.limits)
	if _, err := g.policy.current(ctx); err != nil {
		return nil, err
	}
	return g, nil
}

// parseUpstream checks a base URL the owner's credential is sent to: https, a host, nothing else.
func parseUpstream(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("upstream URL: %w", err)
	}
	if u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("upstream URL %s: want https://host[:port], nothing else", u.Redacted())
	}
	return &url.URL{Scheme: u.Scheme, Host: u.Host}, nil
}

// newTransport returns the transport to GitHub. It uses no proxy from the environment, so the
// credential goes to the upstream host only, and it leaves bodies as they are: content encodings
// pass through, so what the client gets is what GitHub sent.
func newTransport(rootCAs *x509.CertPool, l limits) *http.Transport {
	return &http.Transport{
		DialContext:            (&net.Dialer{Timeout: l.dial, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:        &tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    l.tlsHandshake,
		ResponseHeaderTimeout:  l.responseHeader,
		ExpectContinueTimeout:  time.Second,
		MaxResponseHeaderBytes: maxHeaderBytes,
		DisableCompression:     true,
		ForceAttemptHTTP2:      true,
		MaxIdleConnsPerHost:    16,
		IdleConnTimeout:        90 * time.Second,
	}
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setDeadline(w, g.limits.answer)
	g.serveGit(w, r)
}

// setDeadline bounds reading the request and writing the answer to d from now. An error means the
// connection does not support deadlines (only in tests); contexts still bound the upstream side.
func setDeadline(w http.ResponseWriter, d time.Duration) {
	rc := http.NewResponseController(w)
	deadline := time.Now().Add(d)
	_ = rc.SetReadDeadline(deadline)
	_ = rc.SetWriteDeadline(deadline)
}

// fail answers a request that is not forwarded. The message reads well after "ghgw: " and says
// what to do next (SPEC.md section 8); git shows it to the agent as "remote: ghgw: ...".
func fail(w http.ResponseWriter, status int, format string, args ...any) {
	h := w.Header()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, "ghgw: "+format+"\n", args...)
}

// isTimeout reports whether err is a deadline or a network timeout.
func isTimeout(err error) bool {
	var ne net.Error
	return errors.Is(err, context.DeadlineExceeded) || errors.As(err, &ne) && ne.Timeout()
}
