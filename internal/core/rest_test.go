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
