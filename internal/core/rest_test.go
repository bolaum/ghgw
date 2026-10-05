package core

import (
	"slices"
	"strings"
	"sync"
	"testing"
)

func TestNewRESTTable(t *testing.T) {
	valid := []RESTOperation{
		{Name: "pulls.list", Method: "GET", Path: "/repos/{owner}/{repo}/pulls", Class: ClassRead},
		{Name: "repos.get", Method: "GET", Path: "/repos/{owner}/{repo}", Class: ClassRead},
		{Name: "pulls.create", Method: "POST", Path: "/repos/{owner}/{repo}/pulls", Class: ClassPR},
		{Name: "rate_limit.get", Method: "GET", Path: "/rate_limit", Class: ClassGlobal},
		{Name: "users.get", Method: "GET", Path: "/user", Class: ClassUnscoped},
		{Name: "pulls.merge", Method: "PUT", Path: "/repos/{owner}/{repo}/pulls/{pull_number}/merge", Class: ClassMerge},
	}
	tests := []struct {
		name    string
		ops     []RESTOperation
		wantErr []string
	}{
		{name: "valid", ops: valid},
		{name: "empty"},
		{
			name: "bad entries",
			ops: []RESTOperation{
				{Name: "Pulls.List", Method: "GET", Path: "/repos/{owner}/{repo}/pulls", Class: ClassRead},
				{Name: "", Method: "GET", Path: "/repos/{owner}/{repo}/pulls", Class: ClassRead},
				{Name: "a.b", Method: "get", Path: "/repos/{owner}/{repo}/a", Class: ClassRead},
				{Name: "a.c", Method: "GET", Path: "/repos/{owner}/{repo}/a", Class: 0},
				{Name: "a.d", Method: "GET", Path: "/repos/{owner}/{repo}/a", Class: ClassUnscoped + 1},
				{Name: "a.e", Method: "POST", Path: "/repos/{owner}/{repo}/a", Class: ClassRead},
				{Name: "a.f", Method: "DELETE", Path: "/meta", Class: ClassGlobal},
				{Name: "a.g", Method: "GET", Path: "repos/{owner}/{repo}/a", Class: ClassRead},
				{Name: "a.h", Method: "GET", Path: "/user/repos", Class: ClassRead},
				{Name: "a.i", Method: "GET", Path: "/repos/{owner}/{repo}x", Class: ClassPR},
				{Name: "a.j", Method: "GET", Path: "/repos/{owner}/{repo}/a", Class: ClassGlobal},
				{Name: "a.k", Method: "GET", Path: "/repos/{owner}/{repo}", Class: ClassUnscoped},
			},
			wantErr: []string{
				"operation Pulls.List: the name must be lowercase dotted words",
				`operation "": the name must be lowercase dotted words`,
				"operation a.b: unknown method get",
				"operation a.c: unknown class 0",
				"operation a.d: unknown class 11",
				"operation a.e: only GET operations can be read or global, not POST",
				"operation a.f: only GET operations can be read or global, not DELETE",
				"operation a.g: path repos/{owner}/{repo}/a must be '/'-separated segments",
				"operation a.h: path /user/repos must start with /repos/{owner}/{repo}",
				"operation a.i: path /repos/{owner}/{repo}x must be '/'-separated segments",
				"operation a.j: path /repos/{owner}/{repo}/a is repository-scoped; use a repository class",
				"operation a.k: path /repos/{owner}/{repo} is repository-scoped; use a repository class",
			},
		},
		{
			name: "global is only rate_limit and meta",
			ops: []RESTOperation{
				{Name: "users.get", Method: "GET", Path: "/user", Class: ClassGlobal},
				{Name: "orgs.members", Method: "GET", Path: "/orgs/{org}/members", Class: ClassGlobal},
			},
			wantErr: []string{
				"operation users.get: only GET /rate_limit and GET /meta can be global",
				"operation orgs.members: only GET /rate_limit and GET /meta can be global",
			},
		},
		{
			name: "hard-rule families cannot be classified otherwise",
			ops: []RESTOperation{
				{Name: "contents.update", Method: "PUT", Path: "/repos/{owner}/{repo}/contents/{path}", Class: ClassPR},
				{Name: "pulls.merge", Method: "PUT", Path: "/repos/{owner}/{repo}/pulls/{pull_number}/merge", Class: ClassPR},
				{Name: "hooks.list", Method: "GET", Path: "/repos/{owner}/{repo}/hooks", Class: ClassRead},
				{Name: "repos.update", Method: "PATCH", Path: "/repos/{owner}/{repo}", Class: ClassPR},
				{Name: "contents.delete", Method: "DELETE", Path: "/repos/{owner}/{repo}/contents/{path}", Class: ClassAdmin},
			},
			wantErr: []string{
				"operation contents.update: PUT /repos/{owner}/{repo}/contents/{path} can reach a hard rule; its class must be code change",
				"operation pulls.merge: PUT /repos/{owner}/{repo}/pulls/{pull_number}/merge can reach a hard rule; its class must be merge",
				"operation hooks.list: GET /repos/{owner}/{repo}/hooks can reach a hard rule; its class must be admin",
				"operation repos.update: PATCH /repos/{owner}/{repo} can reach a hard rule; its class must be admin",
				"operation contents.delete: DELETE /repos/{owner}/{repo}/contents/{path} can reach a hard rule; its class must be code change",
			},
		},
		{
			name: "duplicates",
			ops: []RESTOperation{
				valid[0],
				valid[0],
				{Name: "pulls.list2", Method: "GET", Path: "/repos/{owner}/{repo}/pulls", Class: ClassRead},
			},
			wantErr: []string{
				"operation pulls.list is defined twice",
				"operations pulls.list and pulls.list2 both use GET /repos/{owner}/{repo}/pulls",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			table, err := NewRESTTable(tt.ops)
			if len(tt.wantErr) == 0 {
				if err != nil {
					t.Fatalf("NewRESTTable() error = %v", err)
				}
				for _, op := range tt.ops {
					if got, ok := table.lookup(op.Name); !ok || got != op {
						t.Errorf("lookup(%q) = %+v, %v; want %+v", op.Name, got, ok, op)
					}
				}
				if _, ok := table.lookup("pulls.unknown"); ok {
					t.Error(`lookup("pulls.unknown") found an operation`)
				}
				return
			}
			checkErrorLines(t, err, tt.wantErr)
			if table != nil {
				t.Errorf("NewRESTTable() returned a table with an error")
			}
		})
	}

	var nilTable *RESTTable
	if _, ok := nilTable.lookup("pulls.list"); ok {
		t.Error("a nil table found an operation")
	}
}

func TestNonCanonicalPathTemplates(t *testing.T) {
	// Anything an upstream could decode or split differently would let a hard-rule path hide from
	// the families, so only canonical templates are accepted.
	for _, tt := range []struct{ name, path string }{
		{"trailing slash", "/repos/{owner}/{repo}/"},
		{"empty segment", "/repos/{owner}/{repo}//pulls"},
		{"dot dot", "/repos/{owner}/{repo}/../x"},
		{"dot", "/repos/{owner}/{repo}/./pulls"},
		{"percent escape of contents", "/repos/{owner}/{repo}/%63ontents/{path}"},
		{"percent escape of hooks", "/repos/{owner}/{repo}/%68ooks"},
		{"escaped dot dot", "/repos/{owner}/{repo}/%2e%2e/x"},
		{"double escape", "/repos/{owner}/{repo}/%2563ontents"},
		{"backslash", "/repos/{owner}/{repo}/a\\b"},
		{"NUL", "/repos/{owner}/{repo}/a\x00"},
		{"newline", "/repos/{owner}/{repo}/a\nb"},
		{"query", "/repos/{owner}/{repo}/pulls?state=all"},
		{"fragment", "/repos/{owner}/{repo}/pulls#x"},
		{"uppercase", "/repos/{owner}/{repo}/Pulls"},
		{"semicolon", "/repos/{owner}/{repo}/a;b"},
		{"unclosed brace", "/repos/{owner}/{repo}/{pull"},
		{"stray brace", "/repos/{owner}/{repo}/pull}"},
		{"empty parameter", "/repos/{owner}/{repo}/{}"},
		{"parameter inside a segment", "/repos/{owner}/{repo}/x{n}"},
		{"two parameters in a segment", "/repos/{owner}/{repo}/{a}{b}"},
		{"uppercase parameter", "/repos/{owner}/{repo}/{A}"},
		{"dotted parameter", "/repos/{owner}/{repo}/{a.b}"},
		{"root", "/"},
		{"empty", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewRESTTable([]RESTOperation{{Name: "a.b", Method: "GET", Path: tt.path, Class: ClassRead}})
			if err == nil || !strings.Contains(err.Error(), "must be '/'-separated segments") {
				t.Errorf("NewRESTTable(%q) error = %v, want a canonical template error", tt.path, err)
			}
		})
	}
}

// TestTemplateParameters checks that a {parameter} cannot hide a hard-rule path: the segment after
// the repository must be literal, and an allowed template is rejected when some value of its
// parameters reaches a hard-rule family.
func TestTemplateParameters(t *testing.T) {
	const repo = "/repos/{owner}/{repo}"
	tests := []struct {
		method, path string
		class        Class
		wantErr      string // empty: accepted
	}{
		{"PUT", repo + "/{resource}/{path}", ClassPR, "must spell out the segment after"},
		{"GET", repo + "/{resource}", ClassRead, "must spell out the segment after"},
		{"DELETE", repo + "/{resource}", ClassCodeChange, "must spell out the segment after"},
		{"PUT", repo + "/pulls/{pull_number}/{action}", ClassPR, "its class must be code change or merge"},
		{"POST", repo + "/actions/workflows/{workflow_id}/{action}", ClassPR, "its class must be trigger"},
		{"GET", repo + "/actions/{section}", ClassRead, "its class must be admin"},
		{"POST", repo + "/actions/{section}/{id}", ClassPR, "its class must be admin"},
		{"POST", repo + "/actions/{section}/{id}/{action}", ClassPR, "its class must be trigger or admin"},
		{"GET", repo + "/branches/{branch}/{part}", ClassRead, "its class must be admin"},
		{"POST", repo + "/branches/{branch}/{action}", ClassPR, "its class must be admin"},
		{"GET", repo + "/dependabot/{kind}", ClassRead, "its class must be admin"},
		{"GET", repo + "/environments/{environment_name}", ClassRead, "its class must be admin"},
		{"POST", repo + "/statuses/{sha}", ClassPR, "its class must be ci result"},

		{"PUT", repo + "/pulls/{pull_number}/{action}", ClassMerge, ""},
		{"PUT", repo + "/pulls/{pull_number}/{action}", ClassCodeChange, ""},
		{"GET", repo + "/pulls/{pull_number}", ClassRead, ""},
		{"POST", repo + "/pulls/{pull_number}/reviews", ClassPR, ""},
		{"PATCH", repo + "/issues/{issue_number}", ClassPR, ""},
		{"POST", repo + "/issues/{issue_number}/comments", ClassPR, ""},
		{"GET", repo + "/branches/{branch}", ClassRead, ""},
		{"GET", repo + "/contents/{path}", ClassRead, ""},
		{"GET", repo + "/actions/runs/{run_id}", ClassRead, ""},
		{"POST", repo + "/actions/runs/{run_id}/rerun", ClassPR, ""},
		{"GET", repo, ClassRead, ""},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path+" "+tt.class.String(), func(t *testing.T) {
			table, err := NewRESTTable([]RESTOperation{{Name: "a.b", Method: tt.method, Path: tt.path, Class: tt.class}})
			switch {
			case tt.wantErr == "" && err != nil:
				t.Errorf("NewRESTTable() error = %v, want none", err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Errorf("NewRESTTable() error = %v, want it to contain %q", err, tt.wantErr)
			case tt.wantErr != "" && table != nil:
				t.Error("NewRESTTable() returned a table with an error")
			}
		})
	}
}

// TestRESTTableCopiesOperations changes the operations a table was built from while deciding
// concurrently (run with -race): decisions do not change.
func TestRESTTableCopiesOperations(t *testing.T) {
	ops := []RESTOperation{{Name: "pulls.create", Method: "POST", Path: "/repos/{owner}/{repo}/pulls", Class: ClassPR}}
	table, err := NewRESTTable(ops)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewPolicy(State{
		Users:  []User{{Name: "a"}},
		Grants: []Grant{grant(t, 1, "user a", []string{"o/*"}, AccessRead, nil, PresetPR)},
		Owners: []string{"o"},
	}, table)
	if err != nil {
		t.Fatal(err)
	}
	req := Request{User: "a", Repo: mustRepo(t, "o/x"), Op: REST{Name: "pulls.create"}}
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 100 {
				if d := p.Decide(req); !d.Allowed || d.Grant.ID != 1 {
					t.Errorf("Decide() = %+v, want allowed by grant 1", d)
					return
				}
			}
		})
	}
	ops[0] = RESTOperation{Name: "pulls.create", Method: "PUT", Path: "/repos/{owner}/{repo}/contents/{path}", Class: ClassCodeChange}
	wg.Wait()
	if d := p.Decide(req); !d.Allowed {
		t.Errorf("after changing the operations, Decide() = %+v, want allowed", d)
	}
}

func TestHardRuleClasses(t *testing.T) {
	const repo = "/repos/{owner}/{repo}"
	tests := []struct {
		method, path string
		want         []Class // nil: no hard rule
	}{
		{"GET", "/rate_limit", nil},
		{"GET", "/meta", nil},
		{"POST", "/rate_limit", []Class{ClassUnscoped}},
		{"GET", "/rate_limit/x", []Class{ClassUnscoped}},
		{"GET", "/user", []Class{ClassUnscoped}},
		{"GET", "/orgs/{org}/repos", []Class{ClassUnscoped}},
		{"GET", "/search/code", []Class{ClassUnscoped}},
		{"GET", "/", []Class{ClassUnscoped}},
		{"GET", "/repos/{owner}/{repo}x", []Class{ClassUnscoped}},
		{"GET", "/repositories/{id}", []Class{ClassUnscoped}},

		{"GET", repo, nil},
		{"PATCH", repo, []Class{ClassAdmin}},
		{"DELETE", repo, []Class{ClassAdmin}},

		{"GET", repo + "/contents/{path}", nil},
		{"PUT", repo + "/contents/{path}", []Class{ClassCodeChange}},
		{"DELETE", repo + "/contents/{path}", []Class{ClassCodeChange}},
		{"GET", repo + "/git/refs/{ref}", nil},
		{"POST", repo + "/git/refs", []Class{ClassCodeChange}},
		{"PATCH", repo + "/git/refs/{ref}", []Class{ClassCodeChange}},
		{"DELETE", repo + "/git/refs/{ref}", []Class{ClassCodeChange}},
		{"POST", repo + "/git/trees", []Class{ClassCodeChange}},
		{"POST", repo + "/git/commits", []Class{ClassCodeChange}},
		{"POST", repo + "/git/blobs", []Class{ClassCodeChange}},
		{"POST", repo + "/git/tags", []Class{ClassCodeChange}},
		{"POST", repo + "/merges", []Class{ClassCodeChange}},
		{"POST", repo + "/merge-upstream", []Class{ClassCodeChange}},
		{"PUT", repo + "/pulls/{pull_number}/update-branch", []Class{ClassCodeChange}},

		{"PUT", repo + "/pulls/{pull_number}/merge", []Class{ClassMerge}},
		{"GET", repo + "/pulls/{pull_number}/merge", nil},
		{"GET", repo + "/pulls", nil},
		{"POST", repo + "/pulls", nil},
		{"PATCH", repo + "/pulls/{pull_number}", nil},
		{"POST", repo + "/issues/{issue_number}/comments", nil},

		{"GET", repo + "/collaborators", []Class{ClassAdmin}},
		{"PUT", repo + "/collaborators/{username}", []Class{ClassAdmin}},
		{"GET", repo + "/invitations", []Class{ClassAdmin}},
		{"GET", repo + "/hooks", []Class{ClassAdmin}},
		{"POST", repo + "/hooks", []Class{ClassAdmin}},
		{"GET", repo + "/keys", []Class{ClassAdmin}},
		{"POST", repo + "/keys", []Class{ClassAdmin}},
		{"GET", repo + "/environments", []Class{ClassAdmin}},
		{"PUT", repo + "/environments/{environment_name}", []Class{ClassAdmin}},
		{"GET", repo + "/rulesets", []Class{ClassAdmin}},
		{"GET", repo + "/actions/secrets", []Class{ClassAdmin}},
		{"PUT", repo + "/actions/secrets/{secret_name}", []Class{ClassAdmin}},
		{"GET", repo + "/actions/organization-secrets", []Class{ClassAdmin}},
		{"GET", repo + "/actions/variables", []Class{ClassAdmin}},
		{"GET", repo + "/actions/organization-variables", []Class{ClassAdmin}},
		{"GET", repo + "/dependabot/secrets", []Class{ClassAdmin}},
		{"GET", repo + "/codespaces/secrets", []Class{ClassAdmin}},
		{"PUT", repo + "/environments/{environment_name}/variables/{name}", []Class{ClassAdmin}},
		{"GET", repo + "/branches/{branch}/protection", []Class{ClassAdmin}},
		{"PUT", repo + "/branches/{branch}/protection", []Class{ClassAdmin}},
		{"POST", repo + "/branches/{branch}/protection/required_signatures", []Class{ClassAdmin}},
		{"POST", repo + "/branches/{branch}/rename", []Class{ClassAdmin}},
		{"GET", repo + "/branches", nil},
		{"GET", repo + "/branches/{branch}", nil},

		{"POST", repo + "/releases", []Class{ClassRelease}},
		{"PATCH", repo + "/releases/{release_id}", []Class{ClassRelease}},
		{"DELETE", repo + "/releases/assets/{asset_id}", []Class{ClassRelease}},
		{"POST", repo + "/releases/generate-notes", []Class{ClassRelease}},
		{"GET", repo + "/releases", nil},
		{"GET", repo + "/releases/latest", nil},

		{"POST", repo + "/statuses/{sha}", []Class{ClassCIResult}},
		{"POST", repo + "/check-runs", []Class{ClassCIResult}},
		{"PATCH", repo + "/check-runs/{check_run_id}", []Class{ClassCIResult}},
		{"POST", repo + "/check-suites", []Class{ClassCIResult}},
		{"POST", repo + "/check-suites/{check_suite_id}/rerequest", []Class{ClassCIResult}},
		{"GET", repo + "/check-runs/{check_run_id}", nil},
		{"GET", repo + "/commits/{ref}/statuses", nil},
		{"GET", repo + "/commits/{ref}/check-runs", nil},

		{"POST", repo + "/dispatches", []Class{ClassTrigger}},
		{"POST", repo + "/actions/workflows/{workflow_id}/dispatches", []Class{ClassTrigger}},
		{"POST", repo + "/deployments", []Class{ClassTrigger}},
		{"POST", repo + "/deployments/{deployment_id}/statuses", []Class{ClassTrigger}},
		{"DELETE", repo + "/deployments/{deployment_id}", []Class{ClassTrigger}},
		{"GET", repo + "/deployments", nil},
		{"GET", repo + "/actions/workflows/{workflow_id}", nil},

		{"POST", repo + "/transfer", []Class{ClassAdmin}},
		{"POST", repo + "/forks", []Class{ClassAdmin}},
		{"GET", repo + "/forks", nil},
		{"PUT", repo + "/topics", []Class{ClassAdmin}},
		{"GET", repo + "/topics", nil},
		{"GET", repo + "/pages", []Class{ClassAdmin}},
		{"POST", repo + "/pages/builds", []Class{ClassAdmin}},
		{"GET", repo + "/autolinks", []Class{ClassAdmin}},
		{"GET", repo + "/vulnerability-alerts", []Class{ClassAdmin}},
		{"PUT", repo + "/automated-security-fixes", []Class{ClassAdmin}},
		{"PUT", repo + "/private-vulnerability-reporting", []Class{ClassAdmin}},
		{"PUT", repo + "/actions/permissions", []Class{ClassAdmin}},
		{"GET", repo + "/actions/permissions/workflow", []Class{ClassAdmin}},
		{"GET", repo + "/actions/runners", []Class{ClassAdmin}},
		{"POST", repo + "/actions/runners/registration-token", []Class{ClassAdmin}},
		{"GET", repo + "/actions/runner-groups", []Class{ClassAdmin}},
		{"PUT", repo + "/actions/oidc/customization/sub", []Class{ClassAdmin}},
		{"DELETE", repo + "/actions/caches", []Class{ClassAdmin}},
		{"DELETE", repo + "/actions/caches/{cache_id}", []Class{ClassAdmin}},
		{"GET", repo + "/actions/cache/usage", []Class{ClassAdmin}},

		// Re-runs stay in the pr preset (SPEC.md 5.3).
		{"GET", repo + "/actions/runs", nil},
		{"POST", repo + "/actions/jobs/{job_id}/rerun", nil},
		{"POST", repo + "/actions/runs/{run_id}/rerun", nil},
		{"POST", repo + "/actions/runs/{run_id}/rerun-failed-jobs", nil},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			if got := hardRuleClasses(tt.method, tt.path); !slices.Equal(got, tt.want) {
				t.Errorf("hardRuleClasses() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClassString(t *testing.T) {
	if got := ClassCodeChange.String(); got != "code change" {
		t.Errorf("ClassCodeChange.String() = %q", got)
	}
	if got := Class(42).String(); got != "class 42" {
		t.Errorf("Class(42).String() = %q", got)
	}
}

func TestPresetAllows(t *testing.T) {
	classes := []Class{ClassRead, ClassPR, ClassGlobal, ClassCodeChange, ClassMerge, ClassAdmin, ClassUnscoped}
	want := map[Preset][]Class{
		PresetNone: nil,
		PresetRead: {ClassRead},
		PresetPR:   {ClassRead, ClassPR},
		"admin":    nil,
	}
	for p, allowed := range want {
		for _, c := range classes {
			wantAllowed := false
			for _, a := range allowed {
				wantAllowed = wantAllowed || a == c
			}
			if got := p.allows(c); got != wantAllowed {
				t.Errorf("Preset(%q).allows(%d) = %v, want %v", p, c, got, wantAllowed)
			}
		}
	}
	for c, want := range map[Class]Preset{ClassRead: PresetRead, ClassPR: PresetPR, ClassMerge: PresetNone, ClassGlobal: PresetNone} {
		if got := presetFor(c); got != want {
			t.Errorf("presetFor(%d) = %q, want %q", c, got, want)
		}
	}
}
