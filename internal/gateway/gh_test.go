package gateway

import (
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestGHAPI opens and comments on a pull request with real gh through the gateway (SPEC.md section
// 16, M7), pages through a list and gets the guidance for what ghgw does not forward.
func TestGHAPI(t *testing.T) {
	gh, err := exec.LookPath("gh")
	if err != nil {
		t.Skip("gh is not installed")
	}
	e := newRESTEnv(t)
	upstream := e.upstream.srv.URL
	e.upstream.set(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		switch r.Method + " " + r.URL.RequestURI() {
		case "POST /repos/bolaum/ghgw/pulls":
			w.Header().Set("Location", upstream+"/repos/bolaum/ghgw/pulls/43")
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{"number": 43, "state": "open"}`)
		case "POST /repos/bolaum/ghgw/issues/43/comments":
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{"id": 9921, "body": "CI is green."}`)
		case "GET /repos/bolaum/ghgw/pulls?state=all&per_page=1":
			w.Header().Set("Link", "<"+upstream+"/repositories/42/pulls?state=all&per_page=1&page=2>; rel=\"next\"")
			fmt.Fprint(w, `[{"number": 43}]`)
		case "GET /repositories/42/pulls?state=all&per_page=1&page=2":
			t.Error("gh followed a link to GitHub's repository ID path upstream")
		case "GET /repos/bolaum/ghgw/pulls?state=all&per_page=1&page=2":
			fmt.Fprint(w, `[{"number": 42}]`)
		default:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"message": "Not Found"}`)
		}
	})

	srv := httptest.NewUnstartedServer(e.gw)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	caFile := filepath.Join(dir, "gateway.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(t *testing.T, args ...string) (string, error) {
		t.Helper()
		cmd := exec.Command(gh, append([]string{"api"}, args...)...)
		cmd.Dir = dir
		cmd.Env = []string{
			"HOME=" + dir,
			"PATH=" + os.Getenv("PATH"),
			"GH_CONFIG_DIR=" + filepath.Join(dir, "gh"),
			"GH_HOST=" + strings.TrimPrefix(srv.URL, "https://"),
			"GH_ENTERPRISE_TOKEN=" + e.keys["pr-agent"],
			"GH_PROMPT_DISABLED=1",
			"GH_NO_UPDATE_NOTIFIER=1",
			"NO_COLOR=1",
			"SSL_CERT_FILE=" + caFile,
		}
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	t.Run("create and comment on a pull request", func(t *testing.T) {
		out, err := run(t, "-X", "POST", "repos/bolaum/ghgw/pulls", "-f", "head=agent/fix-42", "-f", "base=main", "-f", "title=core: fix the glob cut", "--jq", ".number")
		if err != nil || out != "43\n" {
			t.Fatalf("gh api pulls = %v\n%s", err, out)
		}
		out, err = run(t, "-X", "POST", "repos/bolaum/ghgw/issues/43/comments", "-f", "body=CI is green.", "--jq", ".id")
		if err != nil || out != "9921\n" {
			t.Fatalf("gh api comments = %v\n%s", err, out)
		}
		reqs, bodies := e.upstream.got()
		if len(reqs) != 2 || !strings.Contains(string(bodies[0]), `"head":"agent/fix-42"`) || reqs[1].Header.Get("Authorization") != "Bearer "+ownerToken {
			t.Errorf("the upstream got %d requests, first body %q", len(reqs), bodies[0])
		}
	})

	t.Run("paginate", func(t *testing.T) {
		out, err := run(t, "--paginate", "repos/bolaum/ghgw/pulls?state=all&per_page=1", "--jq", ".[].number")
		if err != nil || out != "43\n42\n" {
			t.Fatalf("gh api --paginate = %v\n%s", err, out)
		}
	})

	for _, tt := range []struct{ name, want string }{
		{"approve", `ghgw: pulls.create-review is forwarded only with "event": "COMMENT"`},
		{"merge", "ghgw: PUT /repos/bolaum/ghgw/pulls/43/merge is not allowed: ghgw never merges pull requests; ask a person to merge"},
		{"graphql", "ghgw: GraphQL is not supported yet. Use the REST API through `gh api`"},
	} {
		t.Run("denied "+tt.name, func(t *testing.T) {
			e.upstream.reset()
			var args []string
			switch tt.name {
			case "approve":
				args = []string{"-X", "POST", "repos/bolaum/ghgw/pulls/43/reviews", "-f", "event=APPROVE"}
			case "merge":
				args = []string{"-X", "PUT", "repos/bolaum/ghgw/pulls/43/merge"}
			case "graphql":
				args = []string{"graphql", "-f", "query={viewer{login}}"}
			}
			out, err := run(t, args...)
			if err == nil || !strings.Contains(out, tt.want) {
				t.Errorf("gh api = %v\n%s\nwant it to fail with %q", err, out, tt.want)
			}
			e.checkNoUpstream(t)
		})
	}
}
