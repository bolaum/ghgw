package gateway

import (
	"encoding/pem"
	"io"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// gitHTTP is a fake GitHub serving the bare repositories under root with git http-backend, to
// the owner's credential only.
func gitHTTP(t *testing.T, root string) http.HandlerFunc {
	t.Helper()
	backend := &cgi.Handler{
		Path:   gitPath(t),
		Args:   []string{"http-backend"},
		Env:    []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1", "GIT_CONFIG_NOSYSTEM=1", "HOME=" + root},
		Stderr: io.Discard,
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if user, password, ok := r.BasicAuth(); !ok || user != "x-access-token" || password != ownerToken {
			w.Header().Set("WWW-Authenticate", `Basic realm="GitHub"`)
			http.Error(w, "bad credentials", http.StatusUnauthorized)
			return
		}
		backend.ServeHTTP(w, r)
	}
}

func gitPath(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is not installed")
	}
	return path
}

// gitEnv runs git isolated from the user's and the system's configuration, trusting the
// certificate in caFile.
type gitEnv struct {
	home, caFile string
}

func (g gitEnv) run(t *testing.T, dir string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(gitPath(t), args...)
	cmd.Dir = dir
	cmd.Env = []string{
		"HOME=" + g.home,
		"PATH=" + os.Getenv("PATH"),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_SSL_CAINFO=" + g.caFile,
		"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com",
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (g gitEnv) mustRun(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := g.run(t, dir, args...)
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

// TestGitClone clones and fetches through the gateway with real git (SPEC.md section 16, M4).
func TestGitClone(t *testing.T) {
	e := newTestEnv(t)
	dir := t.TempDir()
	root := filepath.Join(dir, "github")
	g := gitEnv{home: dir, caFile: filepath.Join(dir, "gateway.pem")}

	// The upstream repository, with one commit.
	bare := filepath.Join(root, "bolaum", "ghgw.git")
	g.mustRun(t, dir, "init", "-q", "--bare", "-b", "main", bare)
	work := filepath.Join(dir, "work")
	g.mustRun(t, dir, "init", "-q", "-b", "main", work)
	var latest string
	commit := func(content string) {
		latest = content
		if err := os.WriteFile(filepath.Join(work, "README"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		g.mustRun(t, work, "add", "README")
		g.mustRun(t, work, "commit", "-q", "-m", content)
		g.mustRun(t, work, "push", "-q", bare, "main")
	}
	commit("first")
	e.upstream.set(gitHTTP(t, root))

	// The gateway over TLS, as git needs, with a certificate git is told to trust.
	srv := httptest.NewUnstartedServer(e.gw)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(g.caFile, pemCert, 0o600); err != nil {
		t.Fatal(err)
	}
	gateway := strings.Replace(srv.URL, "https://", "https://x:"+e.keys["rpi01-agent"]+"@", 1)

	for _, version := range []string{"0", "1", "2"} {
		t.Run("protocol "+version, func(t *testing.T) {
			clone := filepath.Join(t.TempDir(), "clone")
			g.mustRun(t, dir, "-c", "protocol.version="+version, "clone", "-q", gateway+"/bolaum/ghgw.git", clone)
			if b, err := os.ReadFile(filepath.Join(clone, "README")); err != nil || string(b) != latest {
				t.Fatalf("cloned README = %q, %v; want %q", b, err, latest)
			}
			commit("second " + version)
			g.mustRun(t, clone, "-c", "protocol.version="+version, "pull", "-q", "--ff-only")
			if b, err := os.ReadFile(filepath.Join(clone, "README")); err != nil || string(b) != "second "+version {
				t.Fatalf("fetched README = %q, %v; want the second commit", b, err)
			}
		})
	}

	t.Run("denied", func(t *testing.T) {
		unknown := strings.Replace(srv.URL, "https://", "https://x:ghgw_"+strings.Repeat("0", 64)+"@", 1)
		tests := []struct {
			name, url, want string
		}{
			{name: "repository not granted", url: gateway + "/acme/secret.git",
				want: "remote: ghgw: rpi01-agent cannot access acme/secret. Repositories allowed: bolaum/*\n"},
			{name: "unknown key", url: unknown + "/bolaum/ghgw.git",
				want: "remote: ghgw: unknown ghgw key; run ghgw setup again with the key the admin gave you, or ask the admin for a new one\n"},
			{name: "repository missing upstream", url: gateway + "/bolaum/missing.git",
				want: "remote: ghgw: GitHub has no repository bolaum/missing that the credential of owner bolaum can read"},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				out, err := g.run(t, dir, "clone", "-q", tt.url, filepath.Join(t.TempDir(), "clone"))
				if err == nil || !strings.Contains(out, tt.want) {
					t.Errorf("git clone = %v\n%s\nwant it to fail with %q", err, out, tt.want)
				}
				if strings.Contains(out, ownerToken) {
					t.Error("git's output holds the owner's credential")
				}
			})
		}
	})
}
