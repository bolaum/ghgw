package gateway

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bolaum/ghgw/internal/policyfile"
	"github.com/bolaum/ghgw/internal/store"
)

// ownerToken is the credential of owner bolaum in tests.
const ownerToken = "github_pat_test_0123456789"

// testEnv is a gateway in front of a fake GitHub, with the users of testPolicy.
type testEnv struct {
	gw         *Gateway
	url        string // the gateway's base URL
	store      *store.Store
	policyPath string
	keys       map[string]string // user name to ghgw key
	logs       *syncBuffer

	upstream *fakeUpstream
}

// testPolicy has one user per case: an enabled agent, a disabled one, and one whose repositories
// are of an owner without a credential. %s are the key hashes, in that order.
const testPolicy = `
groups:
  agents:
    grants:
      - id: 1
        repos: ["bolaum/*"]
        access: read
users:
  rpi01-agent:
    key_hash: %s
    groups: [agents]
  off-agent:
    key_hash: %s
    disabled: true
    groups: [agents]
  acme-agent:
    key_hash: %s
    grants:
      - id: 2
        repos: ["acme/app"]
        access: read
`

var testUsers = []string{"rpi01-agent", "off-agent", "acme-agent"}

// fakeUpstream is a fake GitHub that records the requests it gets and answers with handler.
type fakeUpstream struct {
	srv *httptest.Server

	mu       sync.Mutex
	handler  http.HandlerFunc
	requests []*http.Request
	bodies   [][]byte
}

func (f *fakeUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(body))
	f.mu.Lock()
	f.requests = append(f.requests, r)
	f.bodies = append(f.bodies, body)
	h := f.handler
	f.mu.Unlock()
	h(w, r)
}

func (f *fakeUpstream) set(h http.HandlerFunc) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.handler = h
	f.requests, f.bodies = nil, nil
}

func (f *fakeUpstream) got() ([]*http.Request, [][]byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests, f.bodies
}

// gitAnswer answers like GitHub's git endpoints.
func gitAnswer(w http.ResponseWriter, r *http.Request) {
	ct := "application/x-git-upload-pack-result"
	if strings.HasSuffix(r.URL.Path, "/info/refs") {
		ct = "application/x-git-upload-pack-advertisement"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Set-Cookie", "session=upstream")
	w.Header().Set("X-GitHub-Request-Id", "1234")
	_, _ = io.WriteString(w, "upstream body")
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// writePolicy writes testPolicy with the hashes of keys to path, private to the current user.
func writePolicy(t *testing.T, path, content string) {
	t.Helper()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	s, _, err := store.Open(ctx, filepath.Join(dir, "state"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.AddOwner(ctx, "bolaum", store.NewSecret(ownerToken), time.Time{}); err != nil {
		t.Fatal(err)
	}

	e := &testEnv{store: s, keys: map[string]string{}, logs: &syncBuffer{}, policyPath: filepath.Join(dir, "policy.yaml")}
	var hashes []any
	for _, u := range testUsers {
		key, hash := store.NewUserKey()
		e.keys[u] = key.Reveal()
		hashes = append(hashes, policyfile.FormatKeyHash(hash))
	}
	writePolicy(t, e.policyPath, fmt.Sprintf(testPolicy, hashes...))

	e.upstream = &fakeUpstream{handler: gitAnswer}
	e.upstream.srv = httptest.NewTLSServer(e.upstream)
	t.Cleanup(e.upstream.srv.Close)
	roots := x509.NewCertPool()
	roots.AddCert(e.upstream.srv.Certificate())

	e.gw, err = New(ctx, Config{
		PolicyPath: e.policyPath,
		Store:      s,
		GitURL:     e.upstream.srv.URL,
		RootCAs:    roots,
		Logger:     slog.New(slog.NewTextHandler(e.logs, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(e.gw)
	t.Cleanup(srv.Close)
	e.url = srv.URL
	return e
}

// do sends a request to the gateway with the key of user (none when user is empty) as git does.
func (e *testEnv) do(t *testing.T, method, path, user string, body io.Reader, header http.Header) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, e.url+path, body)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range header {
		req.Header[k] = v
	}
	if user != "" {
		req.SetBasicAuth("x", e.keys[user])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, string(b)
}

const advertisement = "/bolaum/ghgw.git/info/refs?service=git-upload-pack"

func TestGatewayDenials(t *testing.T) {
	e := newTestEnv(t)
	unknownKey, _ := store.NewUserKey()
	tests := []struct {
		name, method, path, user string
		header                   http.Header
		wantStatus               int
		wantBody                 string
	}{
		{name: "no key", method: "GET", path: advertisement,
			wantStatus: 401, wantBody: "ghgw: this gateway needs a ghgw key; ask the admin for one and run ghgw setup with it\n"},
		{name: "unknown key", method: "GET", path: advertisement,
			header:     http.Header{"Authorization": {"token " + unknownKey.Reveal()}},
			wantStatus: 401, wantBody: "ghgw: unknown ghgw key; run ghgw setup again"},
		{name: "malformed key", method: "GET", path: advertisement,
			header:     http.Header{"Authorization": {"Bearer ghp_abc"}},
			wantStatus: 401, wantBody: "ghgw: unknown ghgw key"},
		{name: "repository not granted", method: "GET", path: "/acme/secret.git/info/refs?service=git-upload-pack", user: "rpi01-agent",
			wantStatus: 403, wantBody: "ghgw: rpi01-agent cannot access acme/secret. Repositories allowed: bolaum/*\n"},
		{name: "repository not granted, service call", method: "POST", path: "/acme/secret.git/git-upload-pack", user: "rpi01-agent",
			wantStatus: 403, wantBody: "ghgw: rpi01-agent cannot access acme/secret. Repositories allowed: bolaum/*\n"},
		{name: "disabled user", method: "GET", path: advertisement, user: "off-agent",
			wantStatus: 403, wantBody: "ghgw: user off-agent is disabled; ask the admin to enable it\n"},
		{name: "owner without credential", method: "GET", path: "/acme/app.git/info/refs?service=git-upload-pack", user: "acme-agent",
			wantStatus: 403, wantBody: "ghgw: ghgw has no credential for owner acme; ask the admin to add one\n"},
		{name: "push", method: "GET", path: "/bolaum/ghgw.git/info/refs?service=git-receive-pack", user: "rpi01-agent",
			wantStatus: 501, wantBody: "ghgw: this gateway does not accept pushes yet"},
		{name: "not git", method: "GET", path: "/bolaum/ghgw.git/HEAD", user: "rpi01-agent",
			wantStatus: 404, wantBody: "ghgw: not a git repository URL; ghgw serves git at /OWNER/REPO.git\n"},
		{name: "invalid repository name", method: "GET", path: "/bolaum/x.git.git/info/refs?service=git-upload-pack", user: "rpi01-agent",
			wantStatus: 404, wantBody: "ghgw: repository bolaum/x.git: write the name without the .git suffix\n"},
		{name: "dumb http", method: "GET", path: "/bolaum/ghgw.git/info/refs", user: "rpi01-agent",
			wantStatus: 400, wantBody: "ghgw: ghgw serves git's smart HTTP protocol only"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e.upstream.set(gitAnswer)
			resp, body := e.do(t, tt.method, tt.path, tt.user, nil, tt.header)
			if resp.StatusCode != tt.wantStatus || !strings.HasPrefix(body, tt.wantBody) {
				t.Errorf("%s %s = %d %q, want %d %q", tt.method, tt.path, resp.StatusCode, body, tt.wantStatus, tt.wantBody)
			}
			if ct := resp.Header.Get("Content-Type"); ct != "text/plain; charset=utf-8" {
				t.Errorf("Content-Type = %q, want text/plain", ct)
			}
			if got := resp.Header.Get("WWW-Authenticate"); (resp.StatusCode == 401) != (got == `Basic realm="ghgw"`) {
				t.Errorf("WWW-Authenticate = %q on a %d", got, resp.StatusCode)
			}
			if reqs, _ := e.upstream.got(); len(reqs) != 0 {
				t.Errorf("the upstream got %d requests, want none", len(reqs))
			}
		})
	}
}

func TestGatewayForwards(t *testing.T) {
	e := newTestEnv(t)
	key := e.keys["rpi01-agent"]
	tests := []struct {
		name, method, path string
		auth               string
		body               string
		wantPath           string
		wantQuery          string
	}{
		{name: "advertisement, basic", method: "GET", path: advertisement, auth: basicAuth("x", key),
			wantPath: "/bolaum/ghgw.git/info/refs", wantQuery: "service=git-upload-pack"},
		{name: "advertisement without .git, token", method: "GET", path: "/bolaum/ghgw/info/refs?service=git-upload-pack", auth: "token " + key,
			wantPath: "/bolaum/ghgw.git/info/refs", wantQuery: "service=git-upload-pack"},
		{name: "case kept, bearer", method: "GET", path: "/BOLAUM/GhGw.GIT/info/refs?service=git-upload-pack", auth: "Bearer " + key,
			wantPath: "/BOLAUM/GhGw.git/info/refs", wantQuery: "service=git-upload-pack"},
		{name: "service call", method: "POST", path: "/bolaum/ghgw.git/git-upload-pack", auth: basicAuth("", key),
			body: "0032want 0123456789012345678901234567890123456789\n00000009done\n", wantPath: "/bolaum/ghgw.git/git-upload-pack"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e.upstream.set(gitAnswer)
			header := http.Header{
				"Authorization":   {tt.auth},
				"Git-Protocol":    {"version=2"},
				"User-Agent":      {"git/2.53.0"},
				"Cookie":          {"session=client"},
				"X-Forwarded-For": {"10.0.0.1"},
				"Content-Type":    {"application/x-git-upload-pack-request"},
			}
			resp, body := e.do(t, tt.method, tt.path, "", strings.NewReader(tt.body), header)
			if resp.StatusCode != 200 || body != "upstream body" {
				t.Fatalf("%s %s = %d %q, want 200 from the upstream", tt.method, tt.path, resp.StatusCode, body)
			}
			if got := resp.Header.Values("Set-Cookie"); len(got) != 0 {
				t.Errorf("Set-Cookie = %q, want it dropped", got)
			}
			if got := resp.Header.Get("X-Github-Request-Id"); got != "" {
				t.Errorf("X-GitHub-Request-Id = %q, want it dropped", got)
			}
			if got := resp.Header.Get("Cache-Control"); got != "no-cache" {
				t.Errorf("Cache-Control = %q, want the upstream's", got)
			}

			reqs, bodies := e.upstream.got()
			if len(reqs) != 1 {
				t.Fatalf("the upstream got %d requests, want 1", len(reqs))
			}
			up := reqs[0]
			if up.Method != tt.method || up.URL.Path != tt.wantPath || up.URL.RawQuery != tt.wantQuery {
				t.Errorf("upstream got %s %s?%s, want %s %s?%s", up.Method, up.URL.Path, up.URL.RawQuery, tt.method, tt.wantPath, tt.wantQuery)
			}
			if string(bodies[0]) != tt.body {
				t.Errorf("upstream body = %q, want %q", bodies[0], tt.body)
			}
			if user, password, ok := up.BasicAuth(); !ok || user != "x-access-token" || password != ownerToken {
				t.Errorf("upstream Authorization = %q, want the owner's credential", up.Header.Get("Authorization"))
			}
			for name, values := range up.Header {
				for _, v := range values {
					if strings.Contains(v, key) {
						t.Errorf("upstream header %s holds the ghgw key", name)
					}
				}
			}
			want := http.Header{
				"Authorization": up.Header["Authorization"],
				"Git-Protocol":  {"version=2"},
				"User-Agent":    {"git/2.53.0"},
				"Content-Type":  {"application/x-git-upload-pack-request"},
				// Set by the transports, not copied from the client.
				"Accept-Encoding": up.Header["Accept-Encoding"],
				"Content-Length":  up.Header["Content-Length"],
			}
			for name := range up.Header {
				if _, ok := want[name]; !ok {
					t.Errorf("upstream got header %s, which is not forwarded", name)
				}
			}
			for name, v := range want {
				if name != "Accept-Encoding" && name != "Content-Length" && strings.Join(up.Header[name], ",") != strings.Join(v, ",") {
					t.Errorf("upstream header %s = %q, want %q", name, up.Header[name], v)
				}
			}
		})
	}
}

func basicAuth(user, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
}

func TestGatewayUpstreamAnswers(t *testing.T) {
	e := newTestEnv(t)
	status := func(code int, header ...string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			for i := 0; i+1 < len(header); i += 2 {
				w.Header().Set(header[i], header[i+1])
			}
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(code)
			_, _ = io.WriteString(w, "upstream says "+ownerToken)
		}
	}
	tests := []struct {
		name       string
		handler    http.HandlerFunc
		wantStatus int
		wantBody   string
	}{
		{name: "credential rejected", handler: status(401, "WWW-Authenticate", `Basic realm="GitHub"`), wantStatus: 502,
			wantBody: "ghgw: GitHub refused the credential of owner bolaum for bolaum/ghgw (401 Unauthorized); ask the admin to check that it is valid (ghgw owner list) and can read bolaum/ghgw\n"},
		{name: "forbidden", handler: status(403), wantStatus: 502,
			wantBody: "ghgw: GitHub refused the credential of owner bolaum for bolaum/ghgw (403 Forbidden)"},
		{name: "not found", handler: status(404), wantStatus: 404,
			wantBody: "ghgw: GitHub has no repository bolaum/ghgw that the credential of owner bolaum can read; check the name, or ask the admin to give the credential access to it\n"},
		{name: "redirect", handler: status(301, "Location", "https://evil.example/x"), wantStatus: 502,
			wantBody: "ghgw: GitHub redirected the request for bolaum/ghgw, and ghgw does not follow redirects"},
		{name: "server error", handler: status(503), wantStatus: 502,
			wantBody: "ghgw: GitHub answered 503 Service Unavailable for bolaum/ghgw; try again later\n"},
		{name: "not git data", handler: status(200), wantStatus: 502,
			wantBody: "ghgw: GitHub did not answer bolaum/ghgw with git data; try again later\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e.upstream.set(tt.handler)
			resp, body := e.do(t, "GET", advertisement, "rpi01-agent", nil, nil)
			if resp.StatusCode != tt.wantStatus || !strings.HasPrefix(body, tt.wantBody) {
				t.Errorf("got %d %q, want %d %q", resp.StatusCode, body, tt.wantStatus, tt.wantBody)
			}
			for _, h := range []string{"WWW-Authenticate", "Location"} {
				if got := resp.Header.Get(h); got != "" {
					t.Errorf("%s = %q, want the upstream's dropped", h, got)
				}
			}
		})
	}
	if strings.Contains(e.logs.String(), ownerToken) {
		t.Error("the log holds the owner's credential")
	}
}

func TestGatewayLimits(t *testing.T) {
	e := newTestEnv(t)
	e.gw.limits.uploadPackBody = 1 << 10
	t.Run("body too large", func(t *testing.T) {
		e.upstream.set(gitAnswer)
		resp, body := e.do(t, "POST", "/bolaum/ghgw.git/git-upload-pack", "rpi01-agent", bytes.NewReader(make([]byte, 1<<20)), nil)
		if resp.StatusCode != 413 || !strings.HasPrefix(body, "ghgw: the request body is larger than the 1024 bytes ghgw forwards") {
			t.Errorf("got %d %q, want 413", resp.StatusCode, body)
		}
	})
	t.Run("upstream too slow", func(t *testing.T) {
		e.gw.transport.ResponseHeaderTimeout = 50 * time.Millisecond
		release := make(chan struct{})
		defer close(release)
		e.upstream.set(func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-release:
			case <-r.Context().Done():
			}
		})
		resp, body := e.do(t, "GET", advertisement, "rpi01-agent", nil, nil)
		if resp.StatusCode != 504 || body != "ghgw: GitHub did not answer in time for bolaum/ghgw; try again later\n" {
			t.Errorf("got %d %q, want 504", resp.StatusCode, body)
		}
	})
}

func TestGatewayReloadsPolicy(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	acme := "/acme/app.git/info/refs?service=git-upload-pack"
	check := func(path string, wantStatus int, wantBody string) {
		t.Helper()
		resp, body := e.do(t, "GET", path, "acme-agent", nil, nil)
		if resp.StatusCode != wantStatus || !strings.HasPrefix(body, wantBody) {
			t.Errorf("GET %s = %d %q, want %d %q", path, resp.StatusCode, body, wantStatus, wantBody)
		}
	}

	// An owner added with ghgw owner add counts at once.
	check(acme, 403, "ghgw: ghgw has no credential for owner acme")
	if err := e.store.AddOwner(ctx, "acme", store.NewSecret(ownerToken), time.Time{}); err != nil {
		t.Fatal(err)
	}
	check(acme, 200, "upstream body")

	// So does an edit of the policy file.
	orig, err := os.ReadFile(e.policyPath)
	if err != nil {
		t.Fatal(err)
	}
	writePolicy(t, e.policyPath, strings.Replace(string(orig), `repos: ["acme/app"]`, `repos: ["acme/other"]`, 1))
	check(acme, 403, "ghgw: acme-agent cannot access acme/app. Repositories allowed: acme/other\n")

	// An invalid file denies everything until it is fixed.
	writePolicy(t, e.policyPath, string(orig)+"\nunknown: field\n")
	check(acme, 503, "ghgw: the gateway has no valid policy, so every request is denied; ask the admin to fix the policy file")
	check(advertisement, 503, "ghgw: the gateway has no valid policy")
	if err := os.Remove(e.policyPath); err != nil {
		t.Fatal(err)
	}
	check(acme, 503, "ghgw: the gateway has no valid policy")
	writePolicy(t, e.policyPath, string(orig))
	check(acme, 200, "upstream body")

	if logs := e.logs.String(); strings.Count(logs, "no valid policy") != 2 || !strings.Contains(logs, "the policy file is valid again") {
		t.Errorf("logs = %s, want each failure logged once and the recovery", logs)
	}
}

func TestNewRefuses(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	invalid := filepath.Join(t.TempDir(), "policy.yaml")
	writePolicy(t, invalid, "users: [")
	tests := []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{name: "plain http upstream", cfg: Config{PolicyPath: e.policyPath, Store: e.store, GitURL: "http://github.com"},
			wantErr: "upstream URL http://github.com: want https://host[:port], nothing else"},
		{name: "upstream with credentials", cfg: Config{PolicyPath: e.policyPath, Store: e.store, GitURL: "https://u:p@github.com"},
			wantErr: "upstream URL https://u:xxxxx@github.com: want https://host[:port], nothing else"},
		{name: "upstream with a path", cfg: Config{PolicyPath: e.policyPath, Store: e.store, GitURL: "https://github.com/x"},
			wantErr: "want https://host[:port]"},
		{name: "missing policy", cfg: Config{PolicyPath: filepath.Join(t.TempDir(), "none.yaml"), Store: e.store, GitURL: DefaultGitURL},
			wantErr: "read the policy file: stat"},
		{name: "invalid policy", cfg: Config{PolicyPath: invalid, Store: e.store, GitURL: DefaultGitURL},
			wantErr: "is invalid; fix it and run again"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(ctx, tt.cfg)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("New() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}
