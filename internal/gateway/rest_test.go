package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bolaum/ghgw/internal/policyfile"
	"github.com/bolaum/ghgw/internal/store"
)

// acmeToken is the credential of owner acme in the REST tests.
const acmeToken = "github_pat_acme_9876543210"

// restPolicy has one user per API preset. %s are the key hashes, in the order of restUsers.
const restPolicy = `
users:
  pr-agent:
    key_hash: %s
    grants:
      - id: 1
        repos: ["bolaum/*", "acme/*", "nocred/*"]
        access: write
        push: ["agent/**"]
        api: pr
  read-agent:
    key_hash: %s
    grants:
      - id: 2
        repos: ["bolaum/*"]
        access: read
        api: read
  git-agent:
    key_hash: %s
    grants:
      - id: 3
        repos: ["bolaum/*"]
        access: read
`

var restUsers = []string{"pr-agent", "read-agent", "git-agent"}

// newRESTEnv is a gateway in front of a fake GitHub API, with the users of restPolicy and the
// owners bolaum and acme.
func newRESTEnv(t *testing.T) *testEnv {
	t.Helper()
	e := newTestEnv(t)
	if err := e.store.AddOwner(context.Background(), "acme", store.NewSecret(acmeToken), time.Time{}); err != nil {
		t.Fatal(err)
	}
	var hashes []any
	for _, u := range restUsers {
		key, hash := store.NewUserKey()
		e.keys[u] = key.Reveal()
		hashes = append(hashes, policyfile.FormatKeyHash(hash))
	}
	writePolicy(t, e.policyPath, fmt.Sprintf(restPolicy, hashes...))
	e.upstream.set(fakeAPI)
	return e
}

// fakeAPI answers like GitHub's REST API, with the request it got in the body.
func fakeAPI(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-GitHub-Request-Id", "1234")
	h.Set("X-RateLimit-Remaining", "4999")
	h.Set("Set-Cookie", "session=upstream")
	h.Set("Github-Authentication-Token-Expiration", "2026-12-01 00:00:00 UTC")
	h.Set("X-OAuth-Scopes", "repo")
	status := http.StatusOK
	if r.Method == http.MethodPost {
		status = http.StatusCreated
	}
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `{"method": %q, "uri": %q}`, r.Method, r.RequestURI)
}

// restDo sends a request to the gateway's API with the key of user (none when user is empty), as
// gh does.
func (e *testEnv) restDo(t *testing.T, method, path, user string, body io.Reader, header http.Header) (*http.Response, string) {
	t.Helper()
	if user != "" {
		header = header.Clone()
		if header == nil {
			header = http.Header{}
		}
		header.Set("Authorization", "token "+e.keys[user])
	}
	return e.do(t, method, path, "", body, header)
}

// checkNoUpstream fails when the upstream got a request.
func (e *testEnv) checkNoUpstream(t *testing.T) {
	t.Helper()
	if reqs, _ := e.upstream.got(); len(reqs) != 0 {
		t.Errorf("the upstream got %d requests (%s %s), want none", len(reqs), reqs[0].Method, reqs[0].RequestURI)
	}
}

// message returns the message of a JSON error answer, or fails.
func message(t *testing.T, resp *http.Response, body string) string {
	t.Helper()
	if ct := resp.Header.Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q, want JSON", ct)
	}
	var m struct{ Message string }
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("the answer %q is not JSON: %v", body, err)
	}
	return m.Message
}

// TestRESTForwards sends every operation of the table through the gateway (docs/operations.md
// section 2): GitHub gets the canonical path with the owner's credential and nothing of the agent's
// but the allowed headers, and the agent gets GitHub's answer.
func TestRESTForwards(t *testing.T) {
	e := newRESTEnv(t)
	const repo = "/api/v3/repos/bolaum/ghgw"
	const up = "/repos/bolaum/ghgw"
	tests := []struct {
		op, method, path, body string
		wantURI                string
		token                  string // the credential GitHub gets, "" for none
	}{
		{"repos.get", "GET", repo, "", up, ownerToken},
		{"repos.get-content", "GET", repo + "/contents", "", up + "/contents", ownerToken},
		{"repos.get-content", "GET", repo + "/contents/go.mod?ref=agent/fix-42", "", up + "/contents/go.mod?ref=agent/fix-42", ownerToken},
		{"repos.get-content", "GET", repo + "/contents/internal/core/rest.go", "", up + "/contents/internal/core/rest.go", ownerToken},
		{"repos.get-content", "GET", repo + "/contents/a%20b%3Bc", "", up + "/contents/a%20b%3Bc", ownerToken},
		{"repos.list-branches", "GET", repo + "/branches?per_page=100", "", up + "/branches?per_page=100", ownerToken},
		{"repos.get-branch", "GET", repo + "/branches/agent/fix-42", "", up + "/branches/agent/fix-42", ownerToken},
		{"repos.get-branch", "GET", repo + "/branches/agent%2Ffix-42", "", up + "/branches/agent/fix-42", ownerToken},
		{"repos.list-commits", "GET", repo + "/commits?sha=main&path=internal/core", "", up + "/commits?sha=main&path=internal/core", ownerToken},
		{"repos.get-commit", "GET", repo + "/commits/3f2a9c1", "", up + "/commits/3f2a9c1", ownerToken},
		{"repos.get-commit", "GET", repo + "/commits/main", "", up + "/commits/main", ownerToken},
		{"pulls.list", "GET", repo + "/pulls?state=open&head=bolaum:agent/fix-42", "", up + "/pulls?state=open&head=bolaum:agent/fix-42", ownerToken},
		{"pulls.get", "GET", repo + "/pulls/42", "", up + "/pulls/42", ownerToken},
		{"pulls.list-commits", "GET", repo + "/pulls/42/commits", "", up + "/pulls/42/commits", ownerToken},
		{"pulls.list-files", "GET", repo + "/pulls/42/files", "", up + "/pulls/42/files", ownerToken},
		{"pulls.list-reviews", "GET", repo + "/pulls/42/reviews", "", up + "/pulls/42/reviews", ownerToken},
		{"pulls.get-review", "GET", repo + "/pulls/42/reviews/2211", "", up + "/pulls/42/reviews/2211", ownerToken},
		{"pulls.list-review-comments", "GET", repo + "/pulls/42/comments", "", up + "/pulls/42/comments", ownerToken},
		{"pulls.get-review-comment", "GET", repo + "/pulls/comments/1873", "", up + "/pulls/comments/1873", ownerToken},
		{"issues.list-for-repo", "GET", repo + "/issues?state=open&labels=bug", "", up + "/issues?state=open&labels=bug", ownerToken},
		{"issues.get", "GET", repo + "/issues/17", "", up + "/issues/17", ownerToken},
		{"issues.list-comments", "GET", repo + "/issues/42/comments", "", up + "/issues/42/comments", ownerToken},
		{"issues.get-comment", "GET", repo + "/issues/comments/9921", "", up + "/issues/comments/9921", ownerToken},
		{"checks.list-for-ref", "GET", repo + "/commits/3f2a9c1/check-runs", "", up + "/commits/3f2a9c1/check-runs", ownerToken},
		{"repos.get-combined-status-for-ref", "GET", repo + "/commits/3f2a9c1/status", "", up + "/commits/3f2a9c1/status", ownerToken},
		{"actions.list-workflow-runs-for-repo", "GET", repo + "/actions/runs?head_sha=3f2a9c1", "", up + "/actions/runs?head_sha=3f2a9c1", ownerToken},
		{"actions.get-workflow-run", "GET", repo + "/actions/runs/1234", "", up + "/actions/runs/1234", ownerToken},
		{"actions.list-jobs-for-workflow-run", "GET", repo + "/actions/runs/1234/jobs", "", up + "/actions/runs/1234/jobs", ownerToken},
		{"actions.download-job-logs-for-workflow-run", "GET", repo + "/actions/jobs/5678/logs", "", up + "/actions/jobs/5678/logs", ownerToken},
		{"pulls.create", "POST", repo + "/pulls", `{"head": "agent/fix-42", "base": "main", "title": "..."}`, up + "/pulls", ownerToken},
		{"pulls.update", "PATCH", repo + "/pulls/42", `{"state": "closed"}`, up + "/pulls/42", ownerToken},
		{"issues.create-comment", "POST", repo + "/issues/42/comments", `{"body": "Rebased on main; CI is green."}`, up + "/issues/42/comments", ownerToken},
		{"pulls.create-review", "POST", repo + "/pulls/42/reviews", `{"event": "COMMENT", "body": "Two problems."}`, up + "/pulls/42/reviews", ownerToken},
		{"pulls.create-reply-for-review-comment", "POST", repo + "/pulls/42/comments/1873/replies", `{"body": "Done in 3f2a9c1."}`, up + "/pulls/42/comments/1873/replies", ownerToken},
		{"actions.re-run-workflow-failed-jobs", "POST", repo + "/actions/runs/1234/rerun-failed-jobs", "", up + "/actions/runs/1234/rerun-failed-jobs", ownerToken},
		{"repos.get on another owner", "GET", "/api/v3/repos/acme/app", "", "/repos/acme/app", acmeToken},
		{"rate-limit.get", "GET", "/api/v3/rate_limit", "", "/rate_limit", ""},
		{"meta.get", "GET", "/api/v3/meta", "", "/meta", ""},
	}
	key := e.keys["pr-agent"]
	for _, tt := range tests {
		t.Run(tt.op+" "+tt.path, func(t *testing.T) {
			e.upstream.set(fakeAPI)
			header := http.Header{
				"Accept":                 {"application/vnd.github+json"},
				"User-Agent":             {"GitHub CLI 2.102.0"},
				"X-Github-Api-Version":   {"2022-11-28"},
				"Content-Type":           {"application/json; charset=utf-8"},
				"Cookie":                 {"session=client"},
				"X-Http-Method-Override": {"DELETE"},
				"X-Forwarded-For":        {"10.0.0.1"},
			}
			resp, body := e.restDo(t, tt.method, tt.path, "pr-agent", strings.NewReader(tt.body), header)
			wantStatus := http.StatusOK
			if tt.method == "POST" {
				wantStatus = http.StatusCreated
			}
			if resp.StatusCode != wantStatus || !strings.Contains(body, fmt.Sprintf("%q", tt.wantURI)) {
				t.Fatalf("%s %s = %d %s, want %d from the upstream for %s", tt.method, tt.path, resp.StatusCode, body, wantStatus, tt.wantURI)
			}
			for name, want := range map[string]string{
				"X-Github-Request-Id": "1234", "X-Ratelimit-Remaining": "4999", "Content-Type": "application/json; charset=utf-8",
				"Set-Cookie": "", "Github-Authentication-Token-Expiration": "", "X-Oauth-Scopes": "",
			} {
				if got := resp.Header.Get(name); got != want {
					t.Errorf("answer header %s = %q, want %q", name, got, want)
				}
			}

			reqs, bodies := e.upstream.got()
			if len(reqs) != 1 {
				t.Fatalf("the upstream got %d requests, want 1", len(reqs))
			}
			up := reqs[0]
			if up.Method != tt.method || up.RequestURI != tt.wantURI {
				t.Errorf("upstream got %s %s, want %s %s", up.Method, up.RequestURI, tt.method, tt.wantURI)
			}
			if string(bodies[0]) != tt.body {
				t.Errorf("upstream body = %q, want %q", bodies[0], tt.body)
			}
			wantAuth := ""
			if tt.token != "" {
				wantAuth = "Bearer " + tt.token
			}
			if got := up.Header.Get("Authorization"); got != wantAuth {
				t.Errorf("upstream Authorization = %q, want %q", got, wantAuth)
			}
			want := map[string]bool{"Accept": true, "User-Agent": true, "X-Github-Api-Version": true, "Content-Type": true,
				"Authorization": tt.token != "", "Accept-Encoding": true, "Content-Length": tt.method != "GET"}
			for name, values := range up.Header {
				if !want[name] {
					t.Errorf("upstream got header %s, which is not forwarded", name)
				}
				for _, v := range values {
					if strings.Contains(v, key) {
						t.Errorf("upstream header %s holds the ghgw key", name)
					}
				}
			}
		})
	}
}

type restDenial struct {
	name, user, method, path string
	header                   http.Header
	body                     string
	wantStatus               int
	wantMessage              string // prefix
}

// TestRESTDenials checks requests that never reach GitHub, with what the agent gets instead.
func TestRESTDenials(t *testing.T) {
	e := newRESTEnv(t)
	const repo = "/api/v3/repos/bolaum/ghgw"
	const (
		unknown = " is not an API operation ghgw forwards; ghgw forwards: "
		admin   = " is not allowed: repository administration is not available through ghgw"
		badPath = "ghgw: the API path "
	)
	unknownKey, _ := store.NewUserKey()
	tests := []restDenial{
		{name: "no key", method: "GET", path: repo + "/pulls",
			wantStatus: 401, wantMessage: "ghgw: this gateway needs a ghgw key; ask the admin for one and run ghgw setup with it"},
		{name: "unknown key", method: "GET", path: repo + "/pulls", header: http.Header{"Authorization": {"token " + unknownKey.Reveal()}},
			wantStatus: 401, wantMessage: "ghgw: unknown ghgw key"},
		{name: "a GitHub token", method: "GET", path: repo + "/pulls", header: http.Header{"Authorization": {"token " + ownerToken}},
			wantStatus: 401, wantMessage: "ghgw: unknown ghgw key"},
		{name: "no API preset", user: "git-agent", method: "GET", path: repo + "/pulls",
			wantStatus: 403, wantMessage: "ghgw: pulls.list on bolaum/ghgw needs API preset read; git-agent has: none (grant 3 of user git-agent)"},
		{name: "pr operation with the read preset", user: "read-agent", method: "POST", path: repo + "/pulls",
			body:       `{"head": "agent/fix-42", "base": "main", "title": "..."}`,
			wantStatus: 403, wantMessage: "ghgw: pulls.create on bolaum/ghgw needs API preset pr; read-agent has: read (grant 2 of user read-agent)"},
		{name: "repository not granted", user: "pr-agent", method: "GET", path: "/api/v3/repos/other/secret/pulls",
			wantStatus: 403, wantMessage: "ghgw: pr-agent cannot access other/secret. Repositories allowed: bolaum/*, acme/*, nocred/*"},
		{name: "owner without credential", user: "pr-agent", method: "GET", path: "/api/v3/repos/nocred/app/pulls",
			wantStatus: 403, wantMessage: "ghgw: ghgw has no credential for owner nocred; ask the admin to add one"},
		{name: "invalid repository name", user: "pr-agent", method: "GET", path: "/api/v3/repos/bolaum/ghgw.git/pulls",
			wantStatus: 404, wantMessage: "ghgw: repository bolaum/ghgw.git: write the name without the .git suffix"},

		// docs/operations.md section 5.4.
		{name: "pulls/comments", user: "pr-agent", method: "GET", path: repo + "/pulls/comments",
			wantStatus: 403, wantMessage: "ghgw: GET /repos/bolaum/ghgw/pulls/comments" + unknown + "GET /repos/{owner}/{repo}/pulls, "},
		{name: "issues/comments", user: "pr-agent", method: "GET", path: repo + "/issues/comments",
			wantStatus: 403, wantMessage: "ghgw: GET /repos/bolaum/ghgw/issues/comments" + unknown + "GET /repos/{owner}/{repo}/issues, "},
		{name: "issues/events", user: "pr-agent", method: "GET", path: repo + "/issues/events",
			wantStatus: 403, wantMessage: "ghgw: GET /repos/bolaum/ghgw/issues/events" + unknown},
		{name: "branch protection", user: "pr-agent", method: "GET", path: repo + "/branches/main/protection",
			wantStatus: 403, wantMessage: "ghgw: GET /repos/bolaum/ghgw/branches/main/protection" + admin},
		{name: "protection of a branch with a slash", user: "pr-agent", method: "GET", path: repo + "/branches/agent/x/protection",
			wantStatus: 403, wantMessage: "ghgw: GET /repos/bolaum/ghgw/branches/agent/x/protection" + admin},
		{name: "escaped branch protection", user: "pr-agent", method: "GET", path: repo + "/branches/main%2Fprotection",
			wantStatus: 403, wantMessage: "ghgw: GET /repos/bolaum/ghgw/branches/main/protection" + admin},
		{name: "double-escaped branch protection", user: "pr-agent", method: "GET", path: repo + "/branches/main%252Fprotection",
			wantStatus: 400, wantMessage: badPath + "/repos/bolaum/ghgw/branches/main%2Fprotection has a % or \\ once decoded"},
		{name: "empty segment", user: "pr-agent", method: "GET", path: repo + "//pulls",
			wantStatus: 400, wantMessage: badPath + "/repos/bolaum/ghgw//pulls has an empty segment"},
		{name: "trailing slash", user: "pr-agent", method: "GET", path: repo + "/pulls/",
			wantStatus: 400, wantMessage: badPath + "/repos/bolaum/ghgw/pulls/ has an empty segment"},
		{name: "dot segment", user: "pr-agent", method: "GET", path: repo + "/./pulls",
			wantStatus: 400, wantMessage: badPath + "/repos/bolaum/ghgw/./pulls has a . or .. segment"},
		{name: "dot-dot segment", user: "pr-agent", method: "GET", path: repo + "/contents/../hooks",
			wantStatus: 400, wantMessage: badPath + "/repos/bolaum/ghgw/contents/../hooks has a . or .. segment"},
		{name: "escaped dot-dot segment", user: "pr-agent", method: "GET", path: repo + "/contents/%2e%2e/hooks",
			wantStatus: 400, wantMessage: badPath + "/repos/bolaum/ghgw/contents/../hooks has a . or .. segment"},
		{name: "contents write", user: "pr-agent", method: "PUT", path: repo + "/contents/README.md", body: `{"message": "x", "content": "eA=="}`,
			wantStatus: 403, wantMessage: "ghgw: PUT /repos/bolaum/ghgw/contents/README.md is not allowed: code changes go through git push only; push to an allowed branch instead"},
		{name: "merge", user: "pr-agent", method: "PUT", path: repo + "/pulls/42/merge",
			wantStatus: 403, wantMessage: "ghgw: PUT /repos/bolaum/ghgw/pulls/42/merge is not allowed: ghgw never merges pull requests; ask a person to merge"},
		{name: "issues.add-labels", user: "pr-agent", method: "POST", path: repo + "/issues/42/labels", body: `{"labels": ["automerge"]}`,
			wantStatus: 403, wantMessage: "ghgw: POST /repos/bolaum/ghgw/issues/42/labels" + unknown},
		{name: "issues.create", user: "pr-agent", method: "POST", path: repo + "/issues", body: `{"title": "x"}`,
			wantStatus: 403, wantMessage: "ghgw: POST /repos/bolaum/ghgw/issues" + unknown},
		{name: "not repository-scoped", user: "pr-agent", method: "GET", path: "/api/v3/user",
			wantStatus: 403, wantMessage: "ghgw: GET /user is not allowed: only repository endpoints (repos/{owner}/{repo}/...), rate_limit and meta are available"},
		{name: "API root", user: "pr-agent", method: "GET", path: "/api/v3/",
			wantStatus: 403, wantMessage: "ghgw: GET / is not allowed: only repository endpoints"},
		{name: "renamed repository", user: "pr-agent", method: "GET", path: "/api/v3/repositories/42/pulls/1",
			wantStatus: 403, wantMessage: "ghgw: GET /repositories/42/pulls/1 is not allowed: ghgw decides by repository name"},
		{name: "global write", user: "pr-agent", method: "POST", path: "/api/v3/rate_limit",
			wantStatus: 403, wantMessage: "ghgw: POST /rate_limit is not allowed: only repository endpoints"},
		{name: "GET with a body", user: "pr-agent", method: "GET", path: repo + "/pulls", body: "x",
			wantStatus: 400, wantMessage: "ghgw: GET requests take no body"},
		{name: "body too large", user: "pr-agent", method: "PATCH", path: repo + "/pulls/42", body: strings.Repeat("x", 1<<20+1),
			wantStatus: 413, wantMessage: "ghgw: the request body is larger than the 1048576 bytes ghgw forwards"},
	}
	for _, c := range []string{"comments", "pulls", "branches-where-head", "check-suites", "statuses"} {
		for _, sep := range []string{"/", "%2F"} {
			tests = append(tests, restDenial{name: "commits " + sep + c, user: "pr-agent", method: "GET", path: repo + "/commits/3f2a9c1" + sep + c,
				wantStatus: 403, wantMessage: "ghgw: GET /repos/bolaum/ghgw/commits/3f2a9c1/" + c + unknown + "GET /repos/{owner}/{repo}/commits, "})
		}
	}
	for _, p := range []string{"/commits/agent/fix-42", "/commits/agent%2Ffix-42"} {
		tests = append(tests, restDenial{name: p, user: "pr-agent", method: "GET", path: repo + p,
			wantStatus: 403, wantMessage: "ghgw: GET /repos/bolaum/ghgw/commits/agent/fix-42" + unknown})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e.upstream.set(fakeAPI)
			var body io.Reader
			if tt.body != "" {
				body = strings.NewReader(tt.body)
			}
			resp, got := e.restDo(t, tt.method, tt.path, tt.user, body, tt.header)
			if msg := message(t, resp, got); resp.StatusCode != tt.wantStatus || !strings.HasPrefix(msg, tt.wantMessage) {
				t.Errorf("%s %s = %d %q, want %d %q", tt.method, tt.path, resp.StatusCode, msg, tt.wantStatus, tt.wantMessage)
			}
			e.checkNoUpstream(t)
		})
	}
}

// TestRESTBodies checks the bodies ghgw reads before forwarding (docs/operations.md section 5.2;
// every case is in core's tests): what passes is forwarded byte for byte, as JSON.
func TestRESTBodies(t *testing.T) {
	e := newRESTEnv(t)
	const (
		reviews = "/api/v3/repos/bolaum/ghgw/pulls/42/reviews"
		pulls   = "/api/v3/repos/bolaum/ghgw/pulls"
	)
	big := `{"event": "COMMENT", "body": "` + strings.Repeat("x", 1<<20) + `"}`
	tests := []struct {
		name, path, body string
		chunked          bool
		wantStatus       int
		wantMessage      string // prefix; empty when forwarded
	}{
		{name: "comment review", path: reviews, body: "{\"event\": \"COMMENT\", \"body\": \"Two problems.\", \"comments\": [{\"path\": \"a.go\", \"line\": 1, \"body\": \"x\"}]}\n", wantStatus: 201},
		{name: "approval", path: reviews, body: `{"event": "APPROVE"}`, wantStatus: 403,
			wantMessage: `ghgw: pulls.create-review is forwarded only with "event": "COMMENT"`},
		{name: "two events", path: reviews, body: `{"event": "COMMENT", "Event": "APPROVE"}`, wantStatus: 403,
			wantMessage: "ghgw: the body of pulls.create-review has the key Event more than once"},
		{name: "event in the query string", path: reviews + "?event=APPROVE", body: `{"event": "COMMENT"}`, wantStatus: 403,
			wantMessage: "ghgw: pulls.create-review takes no query string through ghgw"},
		{name: "trailing data", path: reviews, body: `{"event": "COMMENT"}{"event": "APPROVE"}`, wantStatus: 403,
			wantMessage: "ghgw: the body of pulls.create-review is not one JSON object"},
		{name: "review over 1 MiB", path: reviews, body: big, wantStatus: 413,
			wantMessage: "ghgw: the request body is larger than the 1048576 bytes ghgw forwards"},
		{name: "chunked review over 1 MiB", path: reviews, body: big, chunked: true, wantStatus: 413,
			wantMessage: "ghgw: the request body is larger than the 1048576 bytes ghgw forwards"},
		{name: "pull request from a branch", path: pulls, body: `{"head": "agent/fix-42", "base": "main", "title": "..."}`, wantStatus: 201},
		{name: "pull request from a private fork", path: pulls, body: `{"head": "o:main", "head_repo": "o/secret", "base": "main"}`, wantStatus: 403,
			wantMessage: "ghgw: pulls.create takes only the keys title, body, head, base, draft, maintainer_can_modify and issue through ghgw, not head_repo"},
		{name: "pull request from owner:branch", path: pulls, body: `{"head": "o:main", "base": "main"}`, wantStatus: 403,
			wantMessage: "ghgw: pulls.create needs a head that is a branch of the same repository"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e.upstream.set(fakeAPI)
			var body io.Reader = strings.NewReader(tt.body)
			if tt.chunked {
				body = io.MultiReader(body)
			}
			// A form content type must not make GitHub read the body as anything but JSON.
			resp, got := e.restDo(t, "POST", tt.path, "pr-agent", body, http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
			if resp.StatusCode != tt.wantStatus {
				t.Fatalf("got %d %s, want %d", resp.StatusCode, got, tt.wantStatus)
			}
			if tt.wantMessage != "" {
				if msg := message(t, resp, got); !strings.HasPrefix(msg, tt.wantMessage) || !strings.Contains(msg, "For example: gh api") && resp.StatusCode == 403 {
					t.Errorf("message = %q, want %q and an example", msg, tt.wantMessage)
				}
				e.checkNoUpstream(t)
				return
			}
			reqs, bodies := e.upstream.got()
			if len(reqs) != 1 || string(bodies[0]) != tt.body {
				t.Fatalf("the upstream got %d requests, body %q; want the body as sent", len(reqs), bodies)
			}
			if ct := reqs[0].Header.Get("Content-Type"); ct != "application/json; charset=utf-8" {
				t.Errorf("upstream Content-Type = %q, want JSON", ct)
			}
		})
	}
}

// TestRESTRewritesHeaders checks that every URL GitHub hands back leads to the gateway, where it
// gets a decision of its own, and never to GitHub with the ghgw key.
func TestRESTRewritesHeaders(t *testing.T) {
	e := newRESTEnv(t)
	upstream := e.upstream.srv.URL
	e.upstream.set(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/bolaum/ghgw/pulls":
			w.Header().Add("Link", "<"+upstream+"/repositories/42/pulls?page=2&labels=a,b>; rel=\"next\", <"+upstream+"/repositories/42/pulls?page=5>; rel=\"last\"")
			w.Header().Add("Link", `<https://evil.example/x>; rel="first", <`+upstream+`/repositories/x/pulls>; rel="prev"`)
		case "/repos/bolaum/moved/pulls/1":
			w.Header().Set("Location", upstream+"/repos/acme/app/pulls/1")
			w.WriteHeader(http.StatusTemporaryRedirect)
			return
		case "/repos/bolaum/renamed/pulls/1":
			w.Header().Set("Location", upstream+"/repositories/42/pulls/1")
			w.WriteHeader(http.StatusMovedPermanently)
			return
		case "/repos/bolaum/away/pulls/1":
			w.Header().Set("Location", "https://evil.example/repos/bolaum/away/pulls/1")
			w.WriteHeader(http.StatusFound)
			return
		case "/repos/bolaum/ghgw/issues/42/comments":
			w.Header().Set("Location", upstream+"/repos/bolaum/ghgw/issues/comments/9921")
		}
		fakeAPI(w, r)
	})

	t.Run("links", func(t *testing.T) {
		resp, _ := e.restDo(t, "GET", "/api/v3/repos/bolaum/ghgw/pulls", "pr-agent", nil, nil)
		want := "<" + e.url + "/api/v3/repos/bolaum/ghgw/pulls?page=2&labels=a,b>; rel=\"next\", <" + e.url + "/api/v3/repos/bolaum/ghgw/pulls?page=5>; rel=\"last\", <" +
			e.url + "/api/v3/repositories/x/pulls>; rel=\"prev\""
		if got := resp.Header.Values("Link"); len(got) != 1 || got[0] != want {
			t.Errorf("Link = %q, want %q", got, want)
		}
	})

	t.Run("location of a created resource", func(t *testing.T) {
		resp, _ := e.restDo(t, "POST", "/api/v3/repos/bolaum/ghgw/issues/42/comments", "pr-agent", strings.NewReader(`{"body": "x"}`), nil)
		if got, want := resp.Header.Get("Location"), e.url+"/api/v3/repos/bolaum/ghgw/issues/comments/9921"; resp.StatusCode != 201 || got != want {
			t.Errorf("got %d with Location %q, want 201 with %q", resp.StatusCode, got, want)
		}
	})

	// A client that follows redirects, as gh does: it keeps its Authorization on the same host.
	follow := func(t *testing.T, path string) (*http.Response, string, []*http.Request) {
		t.Helper()
		e.upstream.reset()
		req, err := http.NewRequest("GET", e.url+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "token "+e.keys["pr-agent"])
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		reqs, _ := e.upstream.got()
		return resp, string(b), reqs
	}

	t.Run("redirect to another owner's repository", func(t *testing.T) {
		resp, body, reqs := follow(t, "/api/v3/repos/bolaum/moved/pulls/1")
		if resp.StatusCode != 200 || !strings.Contains(body, `"/repos/acme/app/pulls/1"`) || len(reqs) != 2 {
			t.Fatalf("got %d %s after %d upstream requests, want acme/app's pull request", resp.StatusCode, body, len(reqs))
		}
		if got := reqs[1].Header.Get("Authorization"); got != "Bearer "+acmeToken {
			t.Errorf("the redirected request used Authorization %q, want acme's credential", got)
		}
	})

	t.Run("redirect of a renamed repository", func(t *testing.T) {
		resp, body, reqs := follow(t, "/api/v3/repos/bolaum/renamed/pulls/1")
		if msg := message(t, resp, body); resp.StatusCode != 403 || !strings.Contains(msg, "use its new name") || len(reqs) != 1 {
			t.Errorf("got %d %q after %d upstream requests, want a denial that names the rename", resp.StatusCode, msg, len(reqs))
		}
	})

	t.Run("redirect to another host", func(t *testing.T) {
		resp, body := e.restDo(t, "GET", "/api/v3/repos/bolaum/away/pulls/1", "pr-agent", nil, nil)
		if msg := message(t, resp, body); resp.StatusCode != 502 || msg != "ghgw: GitHub redirected pulls.get on bolaum/away to another host, and ghgw follows no redirect there" {
			t.Errorf("got %d %q, want 502", resp.StatusCode, msg)
		}
		if got := resp.Header.Get("Location"); got != "" {
			t.Errorf("Location = %q, want none", got)
		}
	})
}

// TestRESTJobLogs checks that the gateway follows the redirect of a job log download itself, so
// the agent never gets the signed URL, and sends the storage host nothing of the owner's or the
// agent's.
func TestRESTJobLogs(t *testing.T) {
	e := newRESTEnv(t)
	const logs = "/api/v3/repos/bolaum/ghgw/actions/jobs/5678/logs"
	var storageReqs []*http.Request
	storage := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		storageReqs = append(storageReqs, r)
		switch r.URL.Path {
		case "/again":
			http.Redirect(w, r, "/log", http.StatusFound)
		case "/denied":
			http.Error(w, "signature expired", http.StatusForbidden)
		default:
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("X-Ms-Request-Id", "storage")
			_, _ = io.WriteString(w, "2026-10-05T12:00:00Z ##[error]go vet failed\n")
		}
	}))
	t.Cleanup(storage.Close)
	redirectTo := func(location string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", location)
			w.WriteHeader(http.StatusFound)
		}
	}
	header := http.Header{"Accept": {"application/vnd.github+json"}, "User-Agent": {"GitHub CLI 2.102.0"}, "X-Agent": {"secret"}}

	t.Run("streamed", func(t *testing.T) {
		storageReqs = nil
		e.upstream.set(redirectTo(storage.URL + "/log?sig=signed-secret"))
		resp, body := e.restDo(t, "GET", logs, "pr-agent", nil, header)
		if resp.StatusCode != 200 || body != "2026-10-05T12:00:00Z ##[error]go vet failed\n" {
			t.Fatalf("got %d %q, want the log", resp.StatusCode, body)
		}
		if got := resp.Header.Get("Location") + resp.Header.Get("X-Ms-Request-Id"); got != "" || resp.Header.Get("Content-Type") != "text/plain" {
			t.Errorf("answer headers = %v, want the log's content type only", resp.Header)
		}
		if len(storageReqs) != 1 {
			t.Fatalf("the storage got %d requests, want 1", len(storageReqs))
		}
		sr := storageReqs[0]
		if sr.URL.RawQuery != "sig=signed-secret" {
			t.Errorf("the storage got %s, want the signed URL", sr.RequestURI)
		}
		for name, values := range sr.Header {
			if name != "User-Agent" && name != "Accept-Encoding" {
				t.Errorf("the storage got header %s: %q", name, values)
			}
			for _, v := range values {
				if strings.Contains(v, "GitHub CLI") || strings.Contains(v, ownerToken) || strings.Contains(v, e.keys["pr-agent"]) {
					t.Errorf("the storage got header %s: %q", name, v)
				}
			}
		}
	})

	for _, tt := range []struct{ name, location, want string }{
		{"http", strings.Replace(storage.URL, "https:", "http:", 1) + "/log", "ghgw: cannot download the job log for actions.download-job-logs-for-workflow-run on bolaum/ghgw: GitHub redirected the job log to a URL that is not https; try again later"},
		{"second redirect", storage.URL + "/again", "ghgw: cannot download the job log for actions.download-job-logs-for-workflow-run on bolaum/ghgw: the log storage answered 302 Found; try again later"},
		{"storage error", storage.URL + "/denied", "ghgw: cannot download the job log for actions.download-job-logs-for-workflow-run on bolaum/ghgw: the log storage answered 403 Forbidden; try again later"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			storageReqs = nil
			e.upstream.set(redirectTo(tt.location))
			resp, body := e.restDo(t, "GET", logs, "pr-agent", nil, header)
			if msg := message(t, resp, body); resp.StatusCode != 502 || msg != tt.want {
				t.Errorf("got %d %q, want 502 %q", resp.StatusCode, msg, tt.want)
			}
			if strings.Contains(body, "/again") || strings.Contains(body, "/denied") {
				t.Errorf("the answer %q holds the storage URL", body)
			}
			if tt.name != "http" && len(storageReqs) != 1 {
				t.Errorf("the storage got %d requests, want 1", len(storageReqs))
			}
		})
	}
}

func TestRESTUpstreamAnswers(t *testing.T) {
	e := newRESTEnv(t)
	const pulls = "/api/v3/repos/bolaum/ghgw/pulls"
	answer := func(status int, body string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Header().Set("WWW-Authenticate", `Bearer realm="GitHub"`)
			w.WriteHeader(status)
			_, _ = io.WriteString(w, body)
		}
	}
	for _, tt := range []struct {
		name       string
		handler    http.HandlerFunc
		wantStatus int
		wantBody   string
	}{
		{"credential rejected", answer(401, `{"message": "Bad credentials `+ownerToken+`"}`), 502,
			`{"message":"ghgw: GitHub refused the credential of owner bolaum for pulls.list on bolaum/ghgw (401 Unauthorized); ask the admin to check that it is valid (ghgw owner list)"}` + "\n"},
		{"not found", answer(404, `{"message": "Not Found"}`), 404, `{"message": "Not Found"}`},
		{"forbidden", answer(403, `{"message": "Resource not accessible by personal access token"}`), 403, `{"message": "Resource not accessible by personal access token"}`},
		{"validation failed", answer(422, `{"message": "Validation Failed"}`), 422, `{"message": "Validation Failed"}`},
		{"server error", answer(502, `{"message": "Server Error"}`), 502, `{"message": "Server Error"}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			e.upstream.set(tt.handler)
			resp, body := e.restDo(t, "GET", pulls, "pr-agent", nil, nil)
			if resp.StatusCode != tt.wantStatus || body != tt.wantBody {
				t.Errorf("got %d %q, want %d %q", resp.StatusCode, body, tt.wantStatus, tt.wantBody)
			}
			if got := resp.Header.Get("WWW-Authenticate"); got != "" {
				t.Errorf("WWW-Authenticate = %q, want GitHub's dropped", got)
			}
		})
	}

	t.Run("answer too large", func(t *testing.T) {
		e.gw.limits.restResponse = 1 << 10
		defer func() { e.gw.limits.restResponse = defaultLimits.restResponse }()
		e.upstream.set(answer(200, strings.Repeat("x", 2<<10)))
		resp, body := e.restDo(t, "GET", pulls, "pr-agent", nil, nil)
		if msg := message(t, resp, body); resp.StatusCode != 502 || msg != "ghgw: GitHub's answer to pulls.list on bolaum/ghgw is larger than the 1024 bytes ghgw passes on" {
			t.Errorf("got %d %q, want 502", resp.StatusCode, msg)
		}

		// Without a length, the answer is cut when it grows too large.
		e.upstream.set(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			for range 4 {
				_, _ = w.Write(bytes.Repeat([]byte("x"), 1<<10))
				http.NewResponseController(w).Flush()
			}
		})
		req, err := http.NewRequest("GET", e.url+pulls, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "token "+e.keys["pr-agent"])
		cut, err := http.DefaultClient.Do(req)
		if err != nil {
			return // aborted before the headers: also fine
		}
		defer cut.Body.Close()
		if b, err := io.ReadAll(cut.Body); err == nil || len(b) > 1<<10 {
			t.Errorf("read %d bytes, %v; want the answer cut at 1024 bytes", len(b), err)
		}
	})

	t.Run("upstream too slow", func(t *testing.T) {
		e.gw.transport.ResponseHeaderTimeout = 50 * time.Millisecond
		defer func() { e.gw.transport.ResponseHeaderTimeout = defaultLimits.responseHeader }()
		release := make(chan struct{})
		defer close(release)
		e.upstream.set(func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-release:
			case <-r.Context().Done():
			}
		})
		resp, body := e.restDo(t, "GET", pulls, "pr-agent", nil, nil)
		if msg := message(t, resp, body); resp.StatusCode != 504 || msg != "ghgw: pulls.list on bolaum/ghgw did not finish in time; try again later" {
			t.Errorf("got %d %q, want 504", resp.StatusCode, msg)
		}
	})

	if strings.Contains(e.logs.String(), ownerToken) {
		t.Error("the log holds the owner's credential")
	}
}

func TestGraphQL(t *testing.T) {
	e := newRESTEnv(t)
	resp, body := e.restDo(t, "POST", "/api/graphql", "pr-agent", strings.NewReader(`{"query": "{viewer{login}}"}`), nil)
	want := `{"data":null,"errors":[{"message":"ghgw: GraphQL is not supported yet. Use the REST API through ` + "`gh api`" + `, e.g.\ngh api repos/{owner}/{repo}/pulls -f title=... -f head=... -f base=..."}]}` + "\n"
	if resp.StatusCode != 200 || body != want {
		t.Errorf("got %d %s, want 200 %s", resp.StatusCode, body, want)
	}
	resp, body = e.restDo(t, "POST", "/api/graphql", "", nil, nil)
	if msg := message(t, resp, body); resp.StatusCode != 401 || !strings.HasPrefix(msg, "ghgw: this gateway needs a ghgw key") {
		t.Errorf("without a key: got %d %q, want 401", resp.StatusCode, msg)
	}
	e.checkNoUpstream(t)
}
