package core

import (
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
				`operation "Pulls.List": the name must be lowercase dotted words`,
				`operation "": the name must be lowercase dotted words`,
				`operation a.b: unknown method "get"`,
				"operation a.c: unknown class 0",
				"operation a.d: unknown class 8",
				"operation a.e: only GET operations can be read or global, not POST",
				"operation a.f: only GET operations can be read or global, not DELETE",
				`operation a.g: path "repos/{owner}/{repo}/a" must start with '/'`,
				`operation a.h: path "/user/repos" must start with /repos/{owner}/{repo}`,
				`operation a.i: path "/repos/{owner}/{repo}x" must start with /repos/{owner}/{repo}`,
				`operation a.j: path "/repos/{owner}/{repo}/a" is repository-scoped; use a repository class`,
				`operation a.k: path "/repos/{owner}/{repo}" is repository-scoped; use a repository class`,
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
				"operation contents.update: PUT /repos/{owner}/{repo}/contents/{path} falls under a hard rule; its class must be code change",
				"operation pulls.merge: PUT /repos/{owner}/{repo}/pulls/{pull_number}/merge falls under a hard rule; its class must be merge",
				"operation hooks.list: GET /repos/{owner}/{repo}/hooks falls under a hard rule; its class must be admin",
				"operation repos.update: PATCH /repos/{owner}/{repo} falls under a hard rule; its class must be admin",
				"operation contents.delete: DELETE /repos/{owner}/{repo}/contents/{path} falls under a hard rule; its class must be code change",
			},
		},
		{
			name: "malformed path templates",
			ops: []RESTOperation{
				{Name: "a.a", Method: "GET", Path: "/repos/{owner}/{repo}/", Class: ClassRead},
				{Name: "a.b", Method: "GET", Path: "/repos/{owner}/{repo}//pulls", Class: ClassRead},
				{Name: "a.c", Method: "GET", Path: "/repos/{owner}/{repo}/../x", Class: ClassRead},
				{Name: "a.d", Method: "GET", Path: "/repos/{owner}/{repo}/./pulls", Class: ClassRead},
			},
			wantErr: []string{
				`operation a.a: path "/repos/{owner}/{repo}/" has an empty, '.' or '..' segment`,
				`operation a.b: path "/repos/{owner}/{repo}//pulls" has an empty, '.' or '..' segment`,
				`operation a.c: path "/repos/{owner}/{repo}/../x" has an empty, '.' or '..' segment`,
				`operation a.d: path "/repos/{owner}/{repo}/./pulls" has an empty, '.' or '..' segment`,
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
		})
	}

	var nilTable *RESTTable
	if _, ok := nilTable.lookup("pulls.list"); ok {
		t.Error("a nil table found an operation")
	}
}

func TestHardRuleClass(t *testing.T) {
	const repo = "/repos/{owner}/{repo}"
	tests := []struct {
		method, path string
		want         Class // 0: no hard rule
	}{
		{"GET", "/rate_limit", 0},
		{"GET", "/meta", 0},
		{"POST", "/rate_limit", ClassUnscoped},
		{"GET", "/rate_limit/x", ClassUnscoped},
		{"GET", "/user", ClassUnscoped},
		{"GET", "/orgs/{org}/repos", ClassUnscoped},
		{"GET", "/search/code", ClassUnscoped},
		{"GET", "/", ClassUnscoped},
		{"GET", "/repos/{owner}/{repo}x", ClassUnscoped},
		{"GET", "/repositories/{id}", ClassUnscoped},

		{"GET", repo, 0},
		{"PATCH", repo, ClassAdmin},
		{"DELETE", repo, ClassAdmin},

		{"GET", repo + "/contents/{path}", 0},
		{"PUT", repo + "/contents/{path}", ClassCodeChange},
		{"DELETE", repo + "/contents/{path}", ClassCodeChange},
		{"GET", repo + "/git/refs/{ref}", 0},
		{"POST", repo + "/git/refs", ClassCodeChange},
		{"PATCH", repo + "/git/refs/{ref}", ClassCodeChange},
		{"DELETE", repo + "/git/refs/{ref}", ClassCodeChange},
		{"POST", repo + "/git/trees", ClassCodeChange},
		{"POST", repo + "/git/commits", ClassCodeChange},
		{"POST", repo + "/git/blobs", ClassCodeChange},
		{"POST", repo + "/git/tags", ClassCodeChange},
		{"POST", repo + "/merges", ClassCodeChange},
		{"POST", repo + "/merge-upstream", ClassCodeChange},
		{"PUT", repo + "/pulls/{pull_number}/update-branch", ClassCodeChange},

		{"PUT", repo + "/pulls/{pull_number}/merge", ClassMerge},
		{"GET", repo + "/pulls/{pull_number}/merge", 0},
		{"GET", repo + "/pulls", 0},
		{"POST", repo + "/pulls", 0},
		{"PATCH", repo + "/pulls/{pull_number}", 0},
		{"POST", repo + "/issues/{issue_number}/comments", 0},

		{"GET", repo + "/collaborators", ClassAdmin},
		{"PUT", repo + "/collaborators/{username}", ClassAdmin},
		{"GET", repo + "/invitations", ClassAdmin},
		{"GET", repo + "/hooks", ClassAdmin},
		{"POST", repo + "/hooks", ClassAdmin},
		{"GET", repo + "/keys", ClassAdmin},
		{"POST", repo + "/keys", ClassAdmin},
		{"GET", repo + "/environments", ClassAdmin},
		{"PUT", repo + "/environments/{environment_name}", ClassAdmin},
		{"GET", repo + "/rulesets", ClassAdmin},
		{"GET", repo + "/actions/secrets", ClassAdmin},
		{"PUT", repo + "/actions/secrets/{secret_name}", ClassAdmin},
		{"GET", repo + "/actions/organization-secrets", ClassAdmin},
		{"GET", repo + "/actions/variables", ClassAdmin},
		{"GET", repo + "/actions/organization-variables", ClassAdmin},
		{"GET", repo + "/dependabot/secrets", ClassAdmin},
		{"GET", repo + "/codespaces/secrets", ClassAdmin},
		{"PUT", repo + "/environments/{environment_name}/variables/{name}", ClassAdmin},
		{"GET", repo + "/branches/{branch}/protection", ClassAdmin},
		{"PUT", repo + "/branches/{branch}/protection", ClassAdmin},
		{"POST", repo + "/branches/{branch}/protection/required_signatures", ClassAdmin},
		{"POST", repo + "/branches/{branch}/rename", ClassAdmin},
		{"GET", repo + "/branches", 0},
		{"GET", repo + "/branches/{branch}", 0},

		{"GET", repo + "/actions/runs", 0},
		{"POST", repo + "/actions/jobs/{job_id}/rerun", 0},
		{"GET", repo + "/releases", 0},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			got, ok := hardRuleClass(tt.method, tt.path)
			if ok != (tt.want != 0) || ok && got != tt.want {
				t.Errorf("hardRuleClass() = %v, %v; want %v", got, ok, tt.want)
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
