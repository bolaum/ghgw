package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
		{"token too long", strings.Repeat("a", 2000), []string{"add", "bolaum", "--api-url", api}, "1 to 1024 characters"},
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
