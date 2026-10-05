package gateway

import (
	"crypto/rand"
	"encoding/pem"
	"fmt"
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

// startTLS serves the gateway over TLS, as git needs, with a certificate g trusts, and HTTP/2 when
// h2 is set.
func startTLS(t *testing.T, e *testEnv, g gitEnv, h2 bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(e.gw)
	srv.EnableHTTP2 = h2
	srv.StartTLS()
	t.Cleanup(srv.Close)
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(g.caFile, pemCert, 0o600); err != nil {
		t.Fatal(err)
	}
	return srv
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

	srv := startTLS(t, e, g, false)
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
				want: "remote: ghgw: rpi01-agent cannot access acme/secret. Repositories allowed: bolaum/*, bolaum/pushable\n"},
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

// TestGitPush pushes through the gateway with real git (SPEC.md section 16, M5): allowed branches
// reach the upstream, and rejected pushes get git's report and change nothing there.
func TestGitPush(t *testing.T) {
	e := newTestEnv(t)
	dir := t.TempDir()
	root := filepath.Join(dir, "github")
	g := gitEnv{home: dir, caFile: filepath.Join(dir, "gateway.pem")}

	bare := filepath.Join(root, "bolaum", "pushable.git")
	g.mustRun(t, dir, "init", "-q", "--bare", "-b", "main", bare)
	g.mustRun(t, bare, "config", "http.receivepack", "true")
	work := filepath.Join(dir, "work")
	g.mustRun(t, dir, "init", "-q", "-b", "main", work)
	g.mustRun(t, work, "commit", "-q", "--allow-empty", "-m", "first")
	g.mustRun(t, work, "push", "-q", bare, "main")
	first := g.mustRun(t, work, "rev-parse", "HEAD")
	g.mustRun(t, work, "commit", "-q", "--allow-empty", "-m", "second")
	g.mustRun(t, work, "tag", "v1")
	second := g.mustRun(t, work, "rev-parse", "HEAD")
	// A pack larger than git's http.postBuffer is sent chunked, while the gateway answers.
	g.mustRun(t, work, "switch", "-q", "-c", "big")
	big := make([]byte, 4<<20)
	if _, err := rand.Read(big); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "big"), big, 0o600); err != nil {
		t.Fatal(err)
	}
	g.mustRun(t, work, "add", "big")
	g.mustRun(t, work, "commit", "-q", "-m", "big")
	g.mustRun(t, work, "switch", "-q", "main")

	git := gitHTTP(t, root)
	e.upstream.set(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/repos/") {
			apiAnswer(w, r)
			return
		}
		git(w, r)
	})
	upstreamRef := func(ref string) string {
		out, _ := g.run(t, bare, "rev-parse", "-q", "--verify", ref)
		return out
	}
	for _, h2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("http2 %v", h2), func(t *testing.T) {
			srv := startTLS(t, e, g, h2)
			remote := strings.Replace(srv.URL, "https://", "https://x:"+e.keys["rpi01-agent"]+"@", 1) + "/bolaum/pushable.git"
			testGitPush(t, e, g, remote, upstreamRef, first, second)
		})
	}
}

func testGitPush(t *testing.T, e *testEnv, g gitEnv, remote string, upstreamRef func(string) string, first, second string) {
	work := filepath.Join(g.home, "work")

	for _, version := range []string{"0", "1", "2"} {
		t.Run("allowed, protocol "+version, func(t *testing.T) {
			branch := "agent/v" + version
			g.mustRun(t, work, "-c", "protocol.version="+version, "push", "-q", remote, "HEAD:"+branch)
			if got := upstreamRef(branch); got != second {
				t.Errorf("upstream %s = %q, want %q", branch, got, second)
			}
			g.mustRun(t, work, "-c", "protocol.version="+version, "push", "-q", remote, ":"+branch)
			if got := upstreamRef(branch); got != "" {
				t.Errorf("upstream %s = %q, want it deleted", branch, got)
			}
		})
	}

	const guidance = "; allowed branches: agent/**)"
	tests := []struct {
		name string
		refs []string
		want []string
	}{
		{name: "default branch", refs: []string{"main"},
			want: []string{" ! [remote rejected] main -> main (ghgw: push to the default branch is not allowed" + guidance}},
		{name: "tag", refs: []string{"v1"},
			want: []string{" ! [remote rejected] v1 -> v1 (ghgw: pushing tags is not allowed" + guidance}},
		{name: "large pack", refs: []string{"big:main"},
			want: []string{" ! [remote rejected] big -> main (ghgw: push to the default branch is not allowed" + guidance}},
		{name: "other branch", refs: []string{"HEAD:feature"},
			want: []string{" ! [remote rejected] HEAD -> feature (ghgw: push to branch feature is not allowed" + guidance}},
		{name: "allowed with a rejected one", refs: []string{"HEAD:agent/x", "main"},
			want: []string{
				" ! [remote rejected] HEAD -> agent/x (ghgw: another ref was rejected)",
				" ! [remote rejected] main -> main (ghgw: push to the default branch is not allowed" + guidance,
			}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e.upstream.reset()
			out, err := g.run(t, work, append([]string{"push", remote}, tt.refs...)...)
			if err == nil {
				t.Fatalf("git push succeeded, want it rejected:\n%s", out)
			}
			for _, want := range tt.want {
				if !strings.Contains(out, want) {
					t.Errorf("git push said\n%s\nwant %q", out, want)
				}
			}
			if pushes := e.upstream.receivePacks(); len(pushes) != 0 {
				t.Errorf("the upstream got %d pushes, want none", len(pushes))
			}
			if got := upstreamRef("main"); got != first {
				t.Errorf("upstream main = %q, want it unchanged", got)
			}
			for _, ref := range []string{"agent/x", "feature", "v1", "big"} {
				if got := upstreamRef(ref); got != "" {
					t.Errorf("upstream %s = %q, want none", ref, got)
				}
			}
		})
	}
}
