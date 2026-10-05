package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bolaum/ghgw/internal/store"
)

const (
	goodToken = "github_pat_good"
	// expiry is how the fake GitHub reports the expiry of goodToken.
	expiry = "2031-01-02 03:04:05 +0200"
)

// fakeGitHub answers GET /users/{owner} like GitHub: it knows bolaum and acme, and only goodToken.
func fakeGitHub(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Header.Get("Authorization") != "Bearer "+goodToken:
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"message": "Bad credentials"}`))
		case r.URL.Path == "/users/down":
			w.WriteHeader(http.StatusBadGateway)
		case r.URL.Path == "/users/sso":
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"message": "Resource protected by organization SAML enforcement."}`))
		case r.URL.Path != "/users/bolaum" && r.URL.Path != "/users/acme":
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"message": "Not Found"}`))
		default:
			w.Header().Set("Github-Authentication-Token-Expiration", expiry)
			w.Write([]byte(`{"login": "x"}`))
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestOwners(t *testing.T) {
	dir := testEnv(t)
	api := fakeGitHub(t)
	tokenFile := filepath.Join(t.TempDir(), "pat")
	if err := os.WriteFile(tokenFile, []byte(goodToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	owner := func(stdin string, args ...string) (string, error) {
		args = append([]string{"owner", "--state-dir", dir}, args...)
		out, stderr, err := run(t, stdin, args...)
		if strings.Contains(out+stderr, goodToken) || err != nil && strings.Contains(err.Error(), goodToken) {
			t.Errorf("ghgw %s shows the token", strings.Join(args, " "))
		}
		return out, err
	}

	if out, err := owner("", "list"); err != nil || out != "no owners; add one with ghgw owner add OWNER\n" {
		t.Errorf("owner list on an empty store = %q, %v", out, err)
	}
	if out, err := owner(goodToken+"\n", "add", "bolaum", "--api-url", api); err != nil || out != "added the credential of owner bolaum (expires: 2031-01-02 01:04 UTC)\n" {
		t.Errorf("owner add from stdin = %q, %v", out, err)
	}
	out, err := owner("", "add", "acme", "--api-url", api, "--token-file", tokenFile, "--json")
	if err != nil || out != `{"name":"acme","expires_at":"2031-01-02T01:04:05Z"}`+"\n" {
		t.Errorf("owner add --token-file --json = %q, %v", out, err)
	}

	out, err = owner("", "list")
	want := "OWNER   EXPIRES               UPDATED\n" +
		"acme    2031-01-02 01:04 UTC  " + time.Now().UTC().Format("2006-01-02") // the time may change
	if err != nil || !strings.HasPrefix(out, want) || strings.Count(out, "\n") != 3 {
		t.Errorf("owner list = %q, %v; want it to start with %q", out, err, want)
	}
	out, err = owner("", "list", "--json")
	var listed []ownerJSON
	if err != nil || json.Unmarshal([]byte(out), &listed) != nil || len(listed) != 2 ||
		listed[1].Name != "bolaum" || listed[1].ExpiresAt == nil || listed[1].UpdatedAt.IsZero() {
		t.Errorf("owner list --json = %q, %v", out, err)
	}

	errs := []struct {
		name  string
		stdin string
		args  []string
		want  string
	}{
		{"exists", goodToken, []string{"add", "bolaum", "--api-url", api}, "owner bolaum already has a credential; to replace it, run ghgw owner remove bolaum first"},
		{"rejected token", "github_pat_bad", []string{"add", "bolaum", "--api-url", api}, "GitHub rejected the token"},
		{"unknown owner", goodToken, []string{"add", "nobody", "--api-url", api}, "GitHub has no user or organization nobody; check the owner name"},
		{"other answer", goodToken, []string{"add", "sso", "--api-url", api}, "GitHub answered 403 Forbidden to the token check (Resource protected by organization SAML enforcement.)"},
		{"answer without a message", goodToken, []string{"add", "down", "--api-url", api}, "GitHub answered 502 Bad Gateway to the token check; try again later"},
		{"unreachable", goodToken, []string{"add", "bolaum", "--api-url", "http://127.0.0.1:1"}, "cannot check the token with GitHub"},
		{"no token", "", []string{"add", "bolaum", "--api-url", api}, "the token from stdin is malformed: the token must be 1 to 1024 characters long"},
		{"token with a space", "github pat", []string{"add", "bolaum", "--api-url", api}, "without spaces or line breaks"},
		{"token too long", strings.Repeat("a", 2000), []string{"add", "bolaum", "--api-url", api}, "the token from stdin is malformed: it is longer than 1024 characters"},
		{"missing token file", "", []string{"add", "bolaum", "--token-file", "/nonexistent"}, "read the token: open /nonexistent"},
		{"bad owner name", goodToken, []string{"add", "../x", "--api-url", api}, "owner ../x must be"},
		{"token as argument", "", []string{"add", "bolaum", goodToken}, "accepts 1 arg(s)"},
		{"remove unknown", "", []string{"remove", "nobody"}, "owner nobody has no credential; ghgw owner list shows the owners"},
	}
	for _, tt := range errs {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := owner(tt.stdin, tt.args...); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want it to contain %q", err, tt.want)
			}
		})
	}

	if out, err := owner("", "remove", "bolaum"); err != nil || out != "removed the credential of owner bolaum\n" {
		t.Errorf("owner remove = %q, %v", out, err)
	}
	if out, err := owner("", "remove", "acme", "--json"); err != nil || out != `{"name":"acme"}`+"\n" {
		t.Errorf("owner remove --json = %q, %v", out, err)
	}
	if out, err := owner("", "list", "--json"); err != nil || out != "[]\n" {
		t.Errorf("owner list --json after removing all = %q, %v", out, err)
	}
}

// TestOwnerAddUntrustedAnswers checks that what the server at --api-url sends cannot show the
// token or terminal escapes, and that a redirect takes the token nowhere.
func TestOwnerAddUntrustedAnswers(t *testing.T) {
	var redirected atomic.Int32
	elsewhere := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected.Add(1) }))
	t.Cleanup(elsewhere.Close)
	// raw answers with status line "HTTP/1.1 " + status, which net/http would not write.
	raw := func(status string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			conn, buf, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			defer conn.Close()
			buf.WriteString("HTTP/1.1 " + status + "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
			buf.Flush()
		}
	}
	redirect := func(code int) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, elsewhere.URL+r.URL.Path, code)
		}
	}
	tests := []struct {
		name    string
		handler http.HandlerFunc
		want    string // in the error, or on stderr when the owner is added
		added   bool
	}{
		{
			name: "message with the token",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`{"message": "token ` + goodToken + ` is not allowed"}`))
			},
			want: "GitHub answered 403 Forbidden to the token check (token [redacted] is not allowed); fix that and try again",
		},
		{name: "reason phrase with the token", handler: raw("403 " + goodToken), want: "GitHub answered 403 Forbidden to the token check; try again later"},
		{name: "reason phrase with terminal escapes", handler: raw("403 \x1b[2J\x1b[Hhidden denial"), want: "GitHub answered 403 Forbidden to the token check; try again later"},
		{name: "unknown status", handler: raw("599 " + goodToken), want: "GitHub answered 599 to the token check; try again later"},
		{
			name: "expiry with the token",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Github-Authentication-Token-Expiration", goodToken)
			},
			want:  "ghgw: warning: GitHub reported a token expiry ghgw cannot read; ghgw owner list will show none",
			added: true,
		},
		{name: "302 redirect", handler: redirect(http.StatusFound), want: "GitHub answered 302 Found to the token check, a redirect ghgw does not follow so that the token goes nowhere else; check --api-url"},
		{name: "307 redirect", handler: redirect(http.StatusTemporaryRedirect), want: "GitHub answered 307 Temporary Redirect to the token check, a redirect"},
		{name: "308 redirect", handler: redirect(http.StatusPermanentRedirect), want: "GitHub answered 308 Permanent Redirect to the token check, a redirect"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := testEnv(t)
			srv := httptest.NewServer(tt.handler)
			t.Cleanup(srv.Close)
			out, stderr, err := run(t, goodToken, "owner", "--state-dir", dir, "add", "bolaum", "--api-url", srv.URL)
			shown := out + stderr
			if err != nil {
				shown += err.Error()
			}
			if strings.Contains(shown, goodToken) {
				t.Errorf("the output shows the token: %q", shown)
			}
			if strings.ContainsRune(shown, '\x1b') {
				t.Errorf("the output has a terminal escape: %q", shown)
			}
			if tt.added {
				if err != nil || !strings.Contains(stderr, tt.want) {
					t.Errorf("owner add = %v, stderr %q; want success and stderr to contain %q", err, stderr, tt.want)
				}
			} else if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want it to contain %q", err, tt.want)
			}
			wantList := "[]\n"
			if tt.added {
				wantList = `[{"name":"bolaum","expires_at":null,`
			}
			if list := mustRun(t, "", "owner", "--state-dir", dir, "list", "--json"); !strings.HasPrefix(list, wantList) {
				t.Errorf("owner list --json = %q, want it to start with %q", list, wantList)
			}
		})
	}
	if n := redirected.Load(); n != 0 {
		t.Errorf("the redirect target got %d requests, want none", n)
	}
}

func TestReadToken(t *testing.T) {
	maxToken := strings.Repeat("a", store.MaxTokenLen)
	tests := []struct {
		name, in, want, wantErr string
	}{
		{name: "line break", in: goodToken + "\n", want: goodToken},
		{name: "longest token", in: maxToken + "\r\n", want: maxToken},
		{name: "longest token and spaces", in: maxToken + strings.Repeat(" ", 16), want: maxToken},
		{name: "more after the spaces", in: maxToken + strings.Repeat(" ", 16) + "b", wantErr: "the token from stdin is malformed: it is longer than 1024 characters"},
		{name: "one too many", in: maxToken + "a", wantErr: "the token from stdin is malformed: the token must be 1 to 1024 characters long"},
		{name: "empty", in: "\n", wantErr: "the token from stdin is malformed: the token must be 1 to 1024 characters long"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := readToken(strings.NewReader(tt.in), "")
			if tt.wantErr != "" {
				if err == nil || err.Error() != tt.wantErr {
					t.Errorf("readToken() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil || got.Reveal() != tt.want {
				t.Errorf("readToken() = %d characters, %v; want %d characters", len(got.Reveal()), err, len(tt.want))
			}
		})
	}
}

func TestParseExpiry(t *testing.T) {
	tests := []struct {
		in      string
		want    time.Time
		wantErr bool
	}{
		{"", time.Time{}, false},
		{"2026-11-01 12:00:00 UTC", time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC), false},
		{"2026-11-01 12:00:00 +0200", time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC), false},
		{"tomorrow", time.Time{}, true},
	}
	for _, tt := range tests {
		got, err := parseExpiry(tt.in)
		if !got.Equal(tt.want) || got.Location() != time.UTC || (err != nil) != tt.wantErr {
			t.Errorf("parseExpiry(%q) = %v, %v; want %v, error %v", tt.in, got, err, tt.want, tt.wantErr)
		}
	}
}

func TestDescribeExpiry(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		expiresAt time.Time
		want      string
	}{
		{time.Time{}, "never"},
		{now.Add(-time.Hour), "2026-10-05 11:00 UTC (expired: remove it and add a new token)"},
		{now, "2026-10-05 12:00 UTC (expired: remove it and add a new token)"},
		{now.Add(6 * 24 * time.Hour), "2026-10-11 12:00 UTC (expires soon: remove it and add a new token)"},
		{now.Add(8 * 24 * time.Hour), "2026-10-13 12:00 UTC"},
	}
	for _, tt := range tests {
		if got := describeExpiry(tt.expiresAt, now); got != tt.want {
			t.Errorf("describeExpiry(%v) = %q, want %q", tt.expiresAt, got, tt.want)
		}
	}
}
