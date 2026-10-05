package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/bolaum/ghgw/internal/store"
)

// gatewayHost is the test gateway's name: gh ignores ports, so a gateway gh uses is on port 443,
// which connectProxy makes it look like.
const gatewayHost = "ghgw.test"

// connectProxy is an HTTPS proxy that takes a CONNECT to gatewayHost on port 443 to addr, and
// refuses any other.
func connectProxy(addr string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Host != gatewayHost+":443" {
			http.Error(w, "this proxy only reaches "+gatewayHost, http.StatusForbidden)
			return
		}
		up, err := net.Dial("tcp", addr)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer up.Close()
		w.WriteHeader(http.StatusOK)
		conn, buf, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		go func() {
			_, _ = io.Copy(up, buf)
			_ = up.(*net.TCPConn).CloseWrite()
		}()
		_, _ = io.Copy(conn, up)
	})
}

// fakeGitHubRepo is GitHub with one repository, bolaum/ghgw, over git's smart HTTP and the REST
// API, for the owner's credential only. It returns the server and the Authorization headers the
// API got.
func fakeGitHubRepo(t *testing.T, git, root string) (*httptest.Server, func() []string) {
	t.Helper()
	backend := &cgi.Handler{
		Path:   git,
		Args:   []string{"http-backend"},
		Env:    []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1", "GIT_CONFIG_NOSYSTEM=1", "HOME=" + root},
		Stderr: io.Discard,
	}
	var mu sync.Mutex
	var apiAuth []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/repos/") {
			mu.Lock()
			apiAuth = append(apiAuth, r.Header.Get("Authorization"))
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			if r.Header.Get("Authorization") != "Bearer "+goodToken || r.URL.Path != "/repos/bolaum/ghgw" {
				w.WriteHeader(http.StatusNotFound)
				fmt.Fprint(w, `{"message": "Not Found"}`)
				return
			}
			fmt.Fprint(w, `{"full_name": "bolaum/ghgw", "default_branch": "main"}`)
			return
		}
		if user, password, ok := r.BasicAuth(); !ok || user != "x-access-token" || password != goodToken {
			w.Header().Set("WWW-Authenticate", `Basic realm="GitHub"`)
			http.Error(w, "bad credentials", http.StatusUnauthorized)
			return
		}
		backend.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(apiAuth)
	}
}

// TestSetupGlobal is the check of SPEC.md section 16 for M8: in a scratch home, one ghgw setup
// --global makes git and gh api go through the gateway, with real git and gh.
func TestSetupGlobal(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is not installed")
	}
	gh, err := exec.LookPath("gh")
	if err != nil {
		t.Skip("gh is not installed")
	}
	ghgw, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	stateDir := testEnv(t)
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}

	// The admin's part: an owner, a key and the policy.
	mustRun(t, goodToken, "owner", "add", "bolaum", "--api-url", fakeGitHub(t), "--state-dir", stateDir)
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
        access: write
        push: ["agent/**"]
        api: pr
`), 0o600); err != nil {
		t.Fatal(err)
	}

	// GitHub, with bolaum/ghgw holding one commit.
	root := filepath.Join(dir, "github")
	work := filepath.Join(dir, "work")
	for _, args := range [][]string{
		{"init", "-q", "--bare", "-b", "main", filepath.Join(root, "bolaum", "ghgw.git")},
		{"init", "-q", "-b", "main", work},
		{"-C", work, "commit", "-q", "--allow-empty", "-m", "first"},
		{"-C", work, "push", "-q", filepath.Join(root, "bolaum", "ghgw.git"), "main"},
	} {
		cmd := exec.Command(git, args...)
		cmd.Env = []string{"HOME=" + dir, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
			"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com", "GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com"}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	upstream, apiAuth := fakeGitHubRepo(t, git, root)
	upstreamRoots := x509.NewCertPool()
	upstreamRoots.AddCert(upstream.Certificate())

	// The gateway, reached as https://ghgw.test through connectProxy.
	certFile, keyFile, _ := writeTestCert(t, dir)
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
			gitURL: upstream.URL, apiURL: upstream.URL, rootCAs: upstreamRoots,
		}, ln, slog.New(slog.NewJSONHandler(logs, nil)))
	}()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serve() = %v", err)
		}
	})
	proxy := httptest.NewServer(connectProxy(ln.Addr().String()))
	t.Cleanup(proxy.Close)

	// The agent's part: everything runs in other processes, in the scratch home, with this test
	// binary as ghgw.
	env := []string{
		"HOME=" + home,
		"PATH=" + os.Getenv("PATH"),
		"HTTPS_PROXY=" + proxy.URL,
		"SSL_CERT_FILE=" + certFile,
		"GIT_SSL_CAINFO=" + certFile,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_AUTHOR_NAME=agent", "GIT_AUTHOR_EMAIL=agent@example.com",
		"GIT_COMMITTER_NAME=agent", "GIT_COMMITTER_EMAIL=agent@example.com",
		"GH_NO_UPDATE_NOTIFIER=1", "GH_PROMPT_DISABLED=1", "NO_COLOR=1",
		runAsGhgw + "=1",
	}
	run := func(t *testing.T, dir string, extra []string, name string, args ...string) (string, error) {
		t.Helper()
		cmd := exec.Command(name, args...)
		cmd.Dir = dir
		cmd.Env = append(slices.Clone(env), extra...)
		out, err := cmd.CombinedOutput()
		if strings.Contains(string(out), k.Key) {
			t.Errorf("the output of %s %s holds the key", filepath.Base(name), strings.Join(args, " "))
		}
		return string(out), err
	}
	mustRunIn := func(t *testing.T, dir string, extra []string, name string, args ...string) string {
		t.Helper()
		out, err := run(t, dir, extra, name, args...)
		if err != nil {
			t.Fatalf("%s %s: %v\n%s", filepath.Base(name), strings.Join(args, " "), err, out)
		}
		return out
	}

	out := mustRunIn(t, home, []string{urlEnv + "=https://" + gatewayHost, tokenEnv + "=" + k.Key}, ghgw, "setup", "--global")
	if n := strings.Count(out, "\nchanged  "); n != 6 || !strings.Contains(out, "user     rpi01-agent\n") {
		t.Errorf("setup changed %d settings, want 6:\n%s", n, out)
	}
	for _, f := range []string{".config/ghgw/config.yaml", ".config/gh/hosts.yml"} {
		if fi, err := os.Stat(filepath.Join(home, f)); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v, want mode 0600", f, err)
		}
	}
	t.Run("again", func(t *testing.T) {
		out := mustRunIn(t, home, nil, ghgw, "setup", "--global")
		if n := strings.Count(out, "\nunchanged  "); n != 6 || strings.Contains(out, "\nchanged") {
			t.Errorf("setup again changed something:\n%s", out)
		}
	})

	clone := filepath.Join(dir, "clone")
	t.Run("git clone", func(t *testing.T) {
		mustRunIn(t, dir, nil, git, "clone", "-q", "https://github.com/bolaum/ghgw", clone)
		if got := mustRunIn(t, clone, nil, git, "log", "--format=%s"); got != "first\n" {
			t.Errorf("cloned history = %q, want the first commit", got)
		}
		for _, remote := range []string{"git@github.com:bolaum/ghgw.git", "ssh://git@github.com/bolaum/ghgw.git"} {
			if got := mustRunIn(t, dir, nil, git, "ls-remote", remote, "main"); !strings.HasSuffix(got, "\trefs/heads/main\n") {
				t.Errorf("git ls-remote %s = %q", remote, got)
			}
		}
	})

	t.Run("git push", func(t *testing.T) {
		mustRunIn(t, clone, nil, git, "commit", "-q", "--allow-empty", "-m", "second")
		// The push reaches the gateway with the key; this gateway does not take pushes yet.
		out, err := run(t, clone, nil, git, "push", "origin", "HEAD:agent/fix")
		if err == nil || !strings.Contains(out, "remote: ghgw: this gateway does not accept pushes yet") {
			t.Errorf("git push = %v\n%s", err, out)
		}
	})

	t.Run("gh api", func(t *testing.T) {
		if got := mustRunIn(t, clone, nil, gh, "api", "repos/{owner}/{repo}", "--jq", ".full_name"); got != "bolaum/ghgw\n" {
			t.Errorf("gh api = %q", got)
		}
		if got := apiAuth(); !slices.Equal(got, []string{"Bearer " + goodToken}) {
			t.Errorf("the API got Authorization %q, want the owner's credential once", got)
		}
	})

	t.Run("whoami", func(t *testing.T) {
		out := mustRunIn(t, home, nil, ghgw, "whoami")
		if !strings.Contains(out, "user     rpi01-agent\n") || !strings.Contains(out, "1      user rpi01-agent  bolaum/*  write   agent/**  pr\n") {
			t.Errorf("whoami =\n%s", out)
		}
	})

	if strings.Contains(logs.String(), k.Key) {
		t.Error("the gateway's log holds the key")
	}
}

func TestClientCommandErrors(t *testing.T) {
	testEnv(t)
	config := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", config)
	key, _ := store.NewUserKey()
	notSetUp := "no gateway is set up (" + filepath.Join(config, "ghgw", "config.yaml") + " does not exist); run ghgw setup --global with GHGW_URL and GHGW_TOKEN"
	tests := []struct {
		name    string
		env     map[string]string
		args    []string
		wantErr string
	}{
		{name: "setup without --global", args: []string{"setup"},
			wantErr: "v0 sets up the whole account only: run ghgw setup --global"},
		{name: "setup the first time without the variables", args: []string{"setup", "--global"}, wantErr: notSetUp},
		{name: "setup without the key", env: map[string]string{urlEnv: "https://ghgw.example"}, args: []string{"setup", "--global"}, wantErr: notSetUp},
		{name: "setup with a bad URL", env: map[string]string{urlEnv: "http://ghgw.example", tokenEnv: key.Reveal()}, args: []string{"setup", "--global"},
			wantErr: "$GHGW_URL: the gateway URL must be https://HOST or https://HOST:PORT, with nothing else"},
		{name: "setup with a bad key", env: map[string]string{urlEnv: "https://ghgw.example", tokenEnv: "ghp_secret"}, args: []string{"setup", "--global"},
			wantErr: "$GHGW_TOKEN: that is not a ghgw key (ghgw_ and 64 lowercase hex characters); use the key the admin gave you"},
		{name: "whoami", args: []string{"whoami"}, wantErr: notSetUp},
		{name: "credential", args: []string{"credential", "get"}, wantErr: notSetUp},
		{name: "credential ignores the variables", env: map[string]string{urlEnv: "https://ghgw.example", tokenEnv: key.Reveal()},
			args: []string{"credential", "get"}, wantErr: notSetUp},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			if _, _, err := run(t, "", tt.args...); err == nil || err.Error() != tt.wantErr {
				t.Errorf("ghgw %s = %v, want %q", strings.Join(tt.args, " "), err, tt.wantErr)
			}
		})
	}
}

func TestCredentialCommand(t *testing.T) {
	testEnv(t)
	config := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", config)
	key, _ := store.NewUserKey()
	if err := os.Mkdir(filepath.Join(config, "ghgw"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(config, "ghgw", "config.yaml"), []byte("url: https://ghgw.example\nkey: "+key.Reveal()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out := mustRun(t, "protocol=https\nhost=ghgw.example\n\n", "credential", "get"); out != "username=ghgw\npassword="+key.Reveal()+"\n" {
		t.Errorf("credential get = %q, want the key", out)
	}
	if out := mustRun(t, "protocol=https\nhost=github.com\n\n", "credential", "get"); out != "" {
		t.Errorf("credential get for github.com = %q, want nothing", out)
	}
}
