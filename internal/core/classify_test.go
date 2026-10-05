package core

import (
	"net/url"
	"reflect"
	"strings"
	"testing"
)

// decodedPath decodes raw once, as the gateway's HTTP server does with a request's path.
func decodedPath(t *testing.T, raw string) string {
	t.Helper()
	p, err := url.PathUnescape(raw)
	if err != nil {
		t.Fatalf("PathUnescape(%q): %v", raw, err)
	}
	return p
}

func TestParseRESTPath(t *testing.T) {
	tests := []struct {
		raw     string // as sent, decoded once before parsing
		want    string // String(): forwarded; empty for an error
		wantErr string
	}{
		{raw: "/", want: "/"},
		{raw: "/rate_limit", want: "/rate_limit"},
		{raw: "/repos/o/r/pulls/42", want: "/repos/o/r/pulls/42"},
		{raw: "/repos/o/r/branches/agent%2Ffix-42", want: "/repos/o/r/branches/agent/fix-42"},
		{raw: "/repos/o/r/branches/main%2Fprotection", want: "/repos/o/r/branches/main/protection"},
		{raw: "/repos/o/r/contents/a%20b%3Fc%23d%3B", want: "/repos/o/r/contents/a%20b%3Fc%23d%3B"},
		{raw: "/repos/o/r/contents/d%C3%A9j%C3%A0", want: "/repos/o/r/contents/d%C3%A9j%C3%A0"},
		{raw: "/repos/o/r/contents/%2e%2eswap", want: "/repos/o/r/contents/..swap"},
		{raw: "/repos/o/r/contents/a+b@c:d", want: "/repos/o/r/contents/a+b@c:d"},

		{raw: "repos/o/r", wantErr: "must start with /"},
		{raw: "/repos/o/r/", wantErr: "an empty segment"},
		{raw: "/repos//o/r", wantErr: "an empty segment"},
		{raw: "/repos/o/r/branches/main%2F", wantErr: "an empty segment"},
		{raw: "/repos/o/r/./pulls", wantErr: "a . or .. segment"},
		{raw: "/repos/o/r/%2e%2e/x", wantErr: "a . or .. segment"},
		{raw: "/repos/o/r/contents/a%2F..%2Fb", wantErr: "a . or .. segment"},
		{raw: "/repos/o/r/branches/main%252Fprotection", wantErr: "a % or \\ once decoded"},
		{raw: "/repos/o/r/contents/%25", wantErr: "a % or \\ once decoded"},
		{raw: "/repos/o/r/contents/a%5Cb", wantErr: "a % or \\ once decoded"},
		{raw: "/repos/o/r/contents/a%00", wantErr: "a control character or invalid UTF-8"},
		{raw: "/repos/o/r/contents/a%0Ab", wantErr: "a control character or invalid UTF-8"},
		{raw: "/repos/o/r/contents/a%7F", wantErr: "a control character or invalid UTF-8"},
		{raw: "/repos/o/r/contents/a%C2%85", wantErr: "a control character or invalid UTF-8"},
		{raw: "/repos/o/r/contents/a%FF", wantErr: "a control character or invalid UTF-8"},
		{raw: "/" + strings.Repeat("a", MaxRESTPathLen), wantErr: "longer than the 8192 ghgw reads"},
		{raw: strings.Repeat("/a", MaxRESTPathSegments+1), wantErr: "has 257 segments, more than the 256 ghgw reads"},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			p, err := ParseRESTPath(decodedPath(t, tt.raw))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("ParseRESTPath() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseRESTPath() error = %v", err)
			}
			if got := p.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
			// What is forwarded decodes to the segments that were decided on.
			again, err := ParseRESTPath(decodedPath(t, p.String()))
			if err != nil || !reflect.DeepEqual(again, p) {
				t.Errorf("the forwarded path parses to %v (%v), want %v", again.segs, err, p.segs)
			}
		})
	}
}

func TestRESTPathRepo(t *testing.T) {
	for _, tt := range []struct{ path, want, wantErr string }{
		{path: "/repos/o/r", want: "o/r"},
		{path: "/repos/Bolaum/GhGw/pulls", want: "Bolaum/GhGw"},
		{path: "/repos/o"},
		{path: "/user/repos"},
		{path: "/repositories/1/pulls"},
		{path: "/"},
		{path: "/repos/o/r.git/pulls", wantErr: "without the .git suffix"},
		{path: "/repos/o/r.wiki", wantErr: "GitHub wikis"},
		{path: "/repos/o:x/r", wantErr: "owner"},
	} {
		t.Run(tt.path, func(t *testing.T) {
			p, err := ParseRESTPath(tt.path)
			if err != nil {
				t.Fatal(err)
			}
			repo, err := p.Repo()
			switch {
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Errorf("Repo() error = %v, want %q", err, tt.wantErr)
			case tt.wantErr == "" && (err != nil || repo.String() != tt.want):
				t.Errorf("Repo() = %q, %v; want %q", repo, err, tt.want)
			}
		})
	}
}

// TestClassify matches requests against the v0 table (docs/operations.md section 5.4): unknown
// operations are "", hard rules on the concrete path are their class.
func TestClassify(t *testing.T) {
	const repo = "/repos/bolaum/ghgw"
	tests := []struct {
		method, raw string
		want        string // operation name, "" for none
		hard        Class  // hard rule on the concrete path, 0 for none
	}{
		// docs/operations.md section 2, workflow by workflow.
		{"GET", repo, "repos.get", 0},
		{"GET", repo + "/contents/docs", "repos.get-content", 0},
		{"GET", repo + "/contents/go.mod", "repos.get-content", 0},
		{"GET", repo + "/branches", "repos.list-branches", 0},
		{"GET", repo + "/branches/agent/fix-42", "repos.get-branch", 0},
		{"GET", repo + "/commits", "repos.list-commits", 0},
		{"GET", repo + "/commits/3f2a9c1", "repos.get-commit", 0},
		{"GET", repo + "/pulls", "pulls.list", 0},
		{"GET", repo + "/pulls/42", "pulls.get", 0},
		{"GET", repo + "/pulls/42/commits", "pulls.list-commits", 0},
		{"GET", repo + "/pulls/42/files", "pulls.list-files", 0},
		{"GET", repo + "/pulls/42/reviews", "pulls.list-reviews", 0},
		{"GET", repo + "/pulls/42/reviews/2211", "pulls.get-review", 0},
		{"GET", repo + "/pulls/42/comments", "pulls.list-review-comments", 0},
		{"GET", repo + "/pulls/comments/1873", "pulls.get-review-comment", 0},
		{"GET", repo + "/issues/42/comments", "issues.list-comments", 0},
		{"GET", repo + "/issues/comments/9921", "issues.get-comment", 0},
		{"GET", repo + "/issues", "issues.list-for-repo", 0},
		{"GET", repo + "/issues/17", "issues.get", 0},
		{"GET", repo + "/commits/3f2a9c1/check-runs", "checks.list-for-ref", 0},
		{"GET", repo + "/commits/3f2a9c1/status", "repos.get-combined-status-for-ref", 0},
		{"GET", repo + "/actions/runs", "actions.list-workflow-runs-for-repo", 0},
		{"GET", repo + "/actions/runs/1234", "actions.get-workflow-run", 0},
		{"GET", repo + "/actions/runs/1234/jobs", "actions.list-jobs-for-workflow-run", 0},
		{"GET", repo + "/actions/jobs/5678/logs", "actions.download-job-logs-for-workflow-run", 0},
		{"POST", repo + "/pulls", "pulls.create", 0},
		{"PATCH", repo + "/pulls/42", "pulls.update", 0},
		{"POST", repo + "/issues/42/comments", "issues.create-comment", 0},
		{"POST", repo + "/pulls/42/comments/1873/replies", "pulls.create-reply-for-review-comment", 0},
		{"POST", repo + "/pulls/42/reviews", "pulls.create-review", 0},
		{"POST", repo + "/actions/runs/1234/rerun-failed-jobs", "actions.re-run-workflow-failed-jobs", 0},
		{"GET", "/rate_limit", "rate-limit.get", 0},
		{"GET", "/meta", "meta.get", 0},

		// Numbers are digits: repository-wide lists are not pull requests or issues.
		{"GET", repo + "/pulls/comments", "", 0},
		{"GET", repo + "/issues/comments", "", 0},
		{"GET", repo + "/issues/events", "", 0},
		{"GET", repo + "/pulls/-1", "", 0},
		{"GET", repo + "/pulls/4%202", "", 0},
		{"GET", repo + "/pulls/%EF%BC%94%EF%BC%92", "", 0}, // fullwidth digits

		// Branches span segments; protection below them is a hard rule however it is spelled.
		{"GET", repo + "/branches/agent%2Ffix-42", "repos.get-branch", 0},
		{"GET", repo + "/branches/main/protection", "repos.get-branch", ClassAdmin},
		{"GET", repo + "/branches/agent/x/protection", "repos.get-branch", ClassAdmin},
		{"GET", repo + "/branches/main%2Fprotection", "repos.get-branch", ClassAdmin},
		{"GET", repo + "/branches/main/PROTECTION", "repos.get-branch", ClassAdmin},
		{"GET", repo + "/branches/main/protection/required_signatures", "repos.get-branch", ClassAdmin},
		{"GET", repo + "/branches/protection", "repos.get-branch", 0},
		{"POST", repo + "/branches/main/rename", "", ClassAdmin},

		// Commit refs are one segment: the reads below commits/{ref} are left out.
		{"GET", repo + "/commits/main", "repos.get-commit", 0},
		{"GET", repo + "/commits/3f2a9c1/comments", "", 0},
		{"GET", repo + "/commits/3f2a9c1/pulls", "", 0},
		{"GET", repo + "/commits/3f2a9c1/branches-where-head", "", 0},
		{"GET", repo + "/commits/3f2a9c1/check-suites", "", 0},
		{"GET", repo + "/commits/3f2a9c1/statuses", "", 0},
		{"GET", repo + "/commits/3f2a9c1%2Fcomments", "", 0},
		{"GET", repo + "/commits/3f2a9c1%2Fstatuses", "", 0},
		{"GET", repo + "/commits/agent/fix-42", "", 0},
		{"GET", repo + "/commits/agent%2Ffix-42", "", 0},

		// Contents: the root directory and any depth.
		{"GET", repo + "/contents", "repos.get-content", 0},
		{"GET", repo + "/contents/internal/core/rest.go", "repos.get-content", 0},
		{"PUT", repo + "/contents/internal/core/rest.go", "", ClassCodeChange},
		{"DELETE", repo + "/contents/x", "", ClassCodeChange},

		// Literals are compared as they are; the families in lowercase.
		{"GET", repo + "/Pulls", "", 0},
		{"get", repo + "/pulls", "", 0},
		{"PUT", repo + "/pulls/1/merge", "", ClassMerge},
		{"PUT", repo + "/pulls/1/MERGE", "", ClassMerge},
		{"PUT", repo + "/pulls/1/merge-async", "", ClassMerge},
		{"PUT", repo + "/pulls/1/update-branch", "", ClassCodeChange},
		{"POST", repo + "/merges", "", ClassCodeChange},
		{"POST", repo + "/git/refs", "", ClassCodeChange},
		{"POST", repo + "/releases", "", ClassRelease},
		{"POST", repo + "/statuses/3f2a9c1", "", ClassCIResult},
		{"POST", repo + "/check-runs", "", ClassCIResult},
		{"POST", repo + "/dispatches", "", ClassTrigger},
		{"POST", repo + "/actions/workflows/ci.yml/dispatches", "", ClassTrigger},
		{"POST", repo + "/actions/runs/1234/approve", "", ClassTrigger},
		{"PATCH", repo, "", ClassAdmin},
		{"DELETE", repo, "", ClassAdmin},
		{"GET", repo + "/hooks", "", ClassAdmin},
		{"GET", repo + "/secret-scanning/alerts", "", ClassAdmin},
		{"GET", repo + "/actions/secrets", "", ClassAdmin},
		{"POST", repo + "/forks", "", ClassAdmin},

		// Left out by choice (docs/operations.md sections 6 and 7).
		{"POST", repo + "/issues/42/labels", "", 0},
		{"POST", repo + "/issues", "", 0},
		{"PATCH", repo + "/issues/42", "", 0},
		{"PATCH", repo + "/issues/comments/9921", "", 0},
		{"DELETE", repo + "/issues/comments/9921", "", 0},
		{"PATCH", repo + "/pulls/comments/1873", "", 0},
		{"POST", repo + "/pulls/42/comments", "", 0},
		{"POST", repo + "/actions/runs/1234/rerun", "", 0},
		{"POST", repo + "/actions/runs/1234/cancel", "", 0},
		{"GET", repo + "/releases", "", 0},
		{"GET", repo + "/actions/runs/1234/logs", "", 0},
		{"GET", repo + "/compare/main...agent", "", 0},
		{"HEAD", repo + "/pulls", "", 0},

		// Not repository-scoped.
		{"GET", "/", "", ClassUnscoped},
		{"GET", "/user", "", ClassUnscoped},
		{"GET", "/search/code", "", ClassUnscoped},
		{"GET", "/repositories/123/pulls", "", ClassUnscoped},
		{"GET", "/repos/bolaum", "", ClassUnscoped},
		{"POST", "/rate_limit", "", ClassUnscoped},
		{"GET", "/RATE_LIMIT", "", ClassUnscoped},
		{"GET", "/Repos/bolaum/ghgw/pulls", "", ClassUnscoped},
	}
	table := DefaultRESTTable()
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.raw, func(t *testing.T) {
			p, err := ParseRESTPath(decodedPath(t, tt.raw))
			if err != nil {
				t.Fatal(err)
			}
			op, _ := table.match(tt.method, p)
			if op.Name != tt.want {
				t.Errorf("match() = %q, want %q", op.Name, tt.want)
			}
			var hard Class
			if classes := p.hardRules(tt.method); len(classes) > 0 {
				hard = classes[0]
			}
			if hard != tt.hard {
				t.Errorf("hardRules() = %v, want %v", hard, tt.hard)
			}
		})
	}
}

func TestDefaultRESTTable(t *testing.T) {
	if _, err := NewRESTTable(operations); err != nil {
		t.Fatalf("the v0 table is invalid: %v", err)
	}
	counts := map[Class]int{}
	for _, op := range operations {
		counts[op.Class]++
	}
	// docs/operations.md: 24 read and 6 pr entries; SPEC.md 5.3: rate_limit and meta.
	if want := map[Class]int{ClassRead: 24, ClassPR: 6, ClassGlobal: 2}; !reflect.DeepEqual(counts, want) {
		t.Errorf("the table has %v entries by class, want %v", counts, want)
	}
	for _, name := range []string{OpCreatePull, OpCreateReview, OpDownloadJobLogs} {
		if _, ok := DefaultRESTTable().lookup(name); !ok {
			t.Errorf("the table has no %s", name)
		}
	}
}

func TestRESTTableShapes(t *testing.T) {
	const repo = "/repos/{owner}/{repo}"
	tests := []struct {
		name    string
		ops     []RESTOperation
		wantErr string
	}{
		{name: "same shape, other parameter names", ops: []RESTOperation{
			{"a.one", "GET", repo + "/pulls/{pull_number}", ClassRead},
			{"a.two", "GET", repo + "/pulls/{issue_number}", ClassRead},
		}, wantErr: "operations a.one and a.two both use GET /repos/{owner}/{repo}/pulls/{issue_number}"},
		{name: "integer and plain parameters", ops: []RESTOperation{
			{"a.one", "GET", repo + "/pulls/{pull_number}", ClassRead},
			{"a.two", "GET", repo + "/pulls/{name}", ClassRead},
		}},
		{name: "other methods", ops: []RESTOperation{
			{"a.one", "GET", repo + "/pulls/{pull_number}", ClassRead},
			{"a.two", "PATCH", repo + "/pulls/{pull_number}", ClassPR},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewRESTTable(tt.ops)
			if tt.wantErr == "" && err != nil || tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Errorf("NewRESTTable() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

// TestPrecedence checks that a literal beats a parameter at the first segment where matching
// templates differ, and an integer parameter beats any other, which beats a spanning one.
func TestPrecedence(t *testing.T) {
	const repo = "/repos/{owner}/{repo}"
	table, err := NewRESTTable([]RESTOperation{
		{"contents.get", "GET", repo + "/contents/{path}", ClassRead},
		{"contents.readme", "GET", repo + "/contents/readme", ClassRead},
		{"branches.get", "GET", repo + "/branches/{branch}", ClassRead},
		{"branches.list", "GET", repo + "/branches", ClassRead},
		{"branches.one", "GET", repo + "/branches/{name}/x", ClassRead},
		{"pulls.get", "GET", repo + "/pulls/{pull_number}", ClassRead},
		{"pulls.named", "GET", repo + "/pulls/{name}", ClassRead},
		{"pulls.comments", "GET", repo + "/pulls/comments", ClassRead},
		// Only the routes listed in spanningRoutes span, whatever their parameter is called.
		{"compare.get", "GET", repo + "/compare/{branch}", ClassRead},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct{ path, want string }{
		{"/repos/o/r/contents", "contents.get"},
		{"/repos/o/r/contents/readme", "contents.readme"},
		{"/repos/o/r/contents/readme/x", "contents.get"},
		{"/repos/o/r/branches", "branches.list"},
		{"/repos/o/r/branches/a", "branches.get"},
		{"/repos/o/r/branches/a/x", "branches.one"},
		{"/repos/o/r/branches/a/b/x", "branches.get"},
		{"/repos/o/r/pulls/42", "pulls.get"},
		{"/repos/o/r/pulls/x42", "pulls.named"},
		{"/repos/o/r/pulls/comments", "pulls.comments"},
		{"/repos/o/r/compare/a", "compare.get"},
		{"/repos/o/r/compare/a/b", ""},
	} {
		p, err := ParseRESTPath(tt.path)
		if err != nil {
			t.Fatal(err)
		}
		if op, _ := table.match("GET", p); op.Name != tt.want {
			t.Errorf("match(%s) = %q, want %q", tt.path, op.Name, tt.want)
		}
	}
}

func TestDecideRESTRequest(t *testing.T) {
	p, err := NewPolicy(State{
		Users: []User{{Name: "agent"}, {Name: "reader"}, {Name: "off", Disabled: true}},
		Grants: []Grant{
			grant(t, 1, "user agent", []string{"bolaum/*"}, AccessWrite, []string{"agent/**"}, PresetPR),
			grant(t, 2, "user reader", []string{"bolaum/*"}, AccessRead, nil, PresetRead),
			grant(t, 3, "user agent", []string{"acme/app"}, AccessRead, nil, PresetRead),
		},
		Owners: []string{"bolaum"},
	}, DefaultRESTTable())
	if err != nil {
		t.Fatal(err)
	}
	const pullsNear = "GET /repos/{owner}/{repo}/pulls, GET /repos/{owner}/{repo}/pulls/{pull_number}, " +
		"GET /repos/{owner}/{repo}/pulls/{pull_number}/commits, GET /repos/{owner}/{repo}/pulls/{pull_number}/files, " +
		"GET /repos/{owner}/{repo}/pulls/{pull_number}/reviews, GET /repos/{owner}/{repo}/pulls/{pull_number}/reviews/{review_id}, " +
		"GET /repos/{owner}/{repo}/pulls/{pull_number}/comments, GET /repos/{owner}/{repo}/pulls/comments/{comment_id}, " +
		"POST /repos/{owner}/{repo}/pulls, PATCH /repos/{owner}/{repo}/pulls/{pull_number}, " +
		"POST /repos/{owner}/{repo}/pulls/{pull_number}/reviews, POST /repos/{owner}/{repo}/pulls/{pull_number}/comments/{comment_id}/replies"
	tests := []struct {
		name, user, method, path string
		want                     result
		wantOp                   string
		// prefix compares the start of the reason only: the list of every operation is long.
		prefix bool
	}{
		{name: "read", user: "agent", method: "GET", path: "/repos/bolaum/ghgw/pulls/42",
			want: allowedBy(1, "user agent"), wantOp: "pulls.get"},
		{name: "pr", user: "agent", method: "POST", path: "/repos/bolaum/ghgw/pulls",
			want: allowedBy(1, "user agent"), wantOp: "pulls.create"},
		{name: "pr with the read preset", user: "reader", method: "POST", path: "/repos/bolaum/ghgw/pulls",
			want:   result{Reason: "pulls.create on bolaum/ghgw needs API preset pr; reader has: read (grant 2 of user reader)"},
			wantOp: "pulls.create"},
		{name: "global", user: "reader", method: "GET", path: "/rate_limit",
			want: result{Allowed: true, Reason: "allowed for every user"}, wantOp: "rate-limit.get"},
		{name: "disabled user", user: "off", method: "GET", path: "/meta",
			want: result{Reason: "user off is disabled; ask the admin to enable it"}},
		{name: "repository not granted", user: "agent", method: "PUT", path: "/repos/other/x/pulls/1/merge",
			want: result{Reason: "agent cannot access other/x. Repositories allowed: bolaum/*, acme/app"}},
		{name: "hard rule on the concrete path", user: "agent", method: "GET", path: "/repos/bolaum/ghgw/branches/main/protection",
			want: result{Reason: "GET /repos/bolaum/ghgw/branches/main/protection is not allowed: repository administration is not available through ghgw"}},
		{name: "merge", user: "agent", method: "PUT", path: "/repos/bolaum/ghgw/pulls/1/merge",
			want: result{Reason: "PUT /repos/bolaum/ghgw/pulls/1/merge is not allowed: ghgw never merges pull requests; ask a person to merge"}},
		{name: "unknown, with the operations of the resource", user: "agent", method: "GET", path: "/repos/bolaum/ghgw/pulls/comments",
			want: result{Reason: "GET /repos/bolaum/ghgw/pulls/comments is not an API operation ghgw forwards; ghgw forwards: " + pullsNear}},
		{name: "unknown resource", user: "agent", method: "GET", path: "/repos/bolaum/ghgw/labels",
			want: result{Reason: "GET /repos/bolaum/ghgw/labels is not an API operation ghgw forwards; ghgw forwards: GET /repos/{owner}/{repo}, GET /repos/{owner}/{repo}/contents/{path}"}, prefix: true},
		{name: "unscoped", user: "agent", method: "GET", path: "/user",
			want: result{Reason: "GET /user is not allowed: only repository endpoints (repos/{owner}/{repo}/...), rate_limit and meta are available"}},
		{name: "renamed repository", user: "agent", method: "GET", path: "/repositories/123/pulls",
			want: result{Reason: "GET /repositories/123/pulls is not allowed: ghgw decides by repository name, and GitHub uses repositories/ID paths for a repository that was renamed or transferred; use its new name (repos/OWNER/NAME/...)"}},
		{name: "owner without credential", user: "agent", method: "GET", path: "/repos/acme/app/pulls",
			want: result{Reason: "ghgw has no credential for owner acme; ask the admin to add one"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path, err := ParseRESTPath(tt.path)
			if err != nil {
				t.Fatal(err)
			}
			repo, err := path.Repo()
			if err != nil {
				t.Fatal(err)
			}
			d := p.Decide(Request{User: tt.user, Repo: repo, Op: RESTRequest{Method: tt.method, Path: path}})
			got := summarize(d)
			if tt.prefix && strings.HasPrefix(got.Reason, tt.want.Reason) {
				got.Reason = tt.want.Reason
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Decide() =\n%+v\nwant\n%+v", got, tt.want)
			}
			if d.Operation != tt.wantOp {
				t.Errorf("Operation = %q, want %q", d.Operation, tt.wantOp)
			}
			if len(d.Reason) > 3*renderBudget {
				t.Errorf("the reason is %d bytes", len(d.Reason))
			}
			checkSafeExplain(t, d)
		})
	}

	t.Run("the repository must be the path's", func(t *testing.T) {
		path, err := ParseRESTPath("/repos/bolaum/ghgw/pulls")
		if err != nil {
			t.Fatal(err)
		}
		for _, repo := range []string{"", "bolaum/other"} {
			var r Repo
			if repo != "" {
				r = mustRepo(t, repo)
			}
			d := p.Decide(Request{User: "agent", Repo: r, Op: RESTRequest{Method: "GET", Path: path}})
			if d.Allowed || !strings.Contains(d.Reason, "is decided on another repository than its path names") {
				t.Errorf("Decide() with repository %q = %+v, want denied", repo, d)
			}
		}
	})
}
