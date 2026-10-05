package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/bolaum/ghgw/internal/core"
)

// TestLocalAdmin is the check of milestone M3 (SPEC.md section 16): a script writes the policy of
// section 6, adds an owner, and explain answers as expected.
func TestLocalAdmin(t *testing.T) {
	dir := testEnv(t)
	api := fakeGitHub(t)
	keyHash := func() string {
		var k keyJSON
		if err := json.Unmarshal([]byte(mustRun(t, "", "key", "new", "--json")), &k); err != nil {
			t.Fatal(err)
		}
		return k.KeyHash
	}
	policy := filepath.Join(t.TempDir(), "policy.yaml")
	err := os.WriteFile(policy, []byte(`
groups:
  agents:
    grants:
      - id: 1
        repos: ["bolaum/*"]
        access: write
        push: ["agent/**"]
        api: pr

users:
  rpi01-agent:
    key_hash: `+keyHash()+`
    groups: [agents]
  devct01-agent:
    key_hash: `+keyHash()+`
    groups: [agents]
    grants:
      - id: 2
        repos: ["acme/ml-lab"]
        access: write
        push: ["agent/**"]
        api: pr
`), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	mustRun(t, goodToken, "owner", "add", "bolaum", "--state-dir", dir, "--api-url", api)

	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "fetch",
			args: []string{"--user", "rpi01-agent", "--repo", "bolaum/ghgw", "--op", "fetch"},
			want: "allowed by grant 1 of group agents",
		},
		{
			name: "push access",
			args: []string{"--user", "rpi01-agent", "--repo", "Bolaum/GHGW", "--op", "push"},
			want: "allowed by grant 1 of group agents",
		},
		{
			name: "push",
			args: []string{"--user", "rpi01-agent", "--repo", "bolaum/ghgw", "--op", "push", "--default-branch", "main",
				"--ref", "agent/fix", "--ref", ":agent/old"},
			want: "allowed by grant 1 of group agents\n" +
				"  refs/heads/agent/fix: allowed by grant 1 of group agents\n" +
				"  refs/heads/agent/old: allowed by grant 1 of group agents",
		},
		{
			name: "push to the default branch and a tag",
			args: []string{"--user", "rpi01-agent", "--repo", "bolaum/ghgw", "--op", "push", "--default-branch", "main",
				"--ref", "agent/fix", "--ref", "main", "--ref", "refs/tags/v1"},
			want: "denied: push to the default branch is not allowed; allowed branches: agent/**\n" +
				"  refs/heads/agent/fix: denied: another ref was rejected\n" +
				"  refs/heads/main: denied: push to the default branch is not allowed\n" +
				"  refs/tags/v1: denied: pushing tags is not allowed",
		},
		{
			name: "push to another branch",
			args: []string{"--user", "rpi01-agent", "--repo", "bolaum/ghgw", "--op", "push", "--default-branch", "main", "--ref", "feature"},
			want: "denied: push to branch feature is not allowed; allowed branches: agent/**\n" +
				"  refs/heads/feature: denied: push to branch feature is not allowed",
		},
		{
			name: "repository of another user's grant",
			args: []string{"--user", "rpi01-agent", "--repo", "acme/ml-lab", "--op", "fetch"},
			want: "denied: rpi01-agent cannot access acme/ml-lab. Repositories allowed: bolaum/*",
		},
		{
			name: "owner without a credential",
			args: []string{"--user", "devct01-agent", "--repo", "acme/ml-lab", "--op", "fetch"},
			want: "denied: ghgw has no credential for owner acme; ask the admin to add one",
		},
		{
			name: "unknown user",
			args: []string{"--user", "laptop-agent", "--repo", "bolaum/ghgw", "--op", "fetch"},
			want: "denied: unknown user laptop-agent; ask the admin to create it",
		},
		{
			name: "REST operation",
			args: []string{"--user", "rpi01-agent", "--repo", "bolaum/ghgw", "--op", "pulls.create"},
			want: "allowed by grant 1 of group agents",
		},
		{
			name: "REST operation outside the table",
			args: []string{"--user", "rpi01-agent", "--repo", "bolaum/ghgw", "--op", "pulls.merge"},
			want: "denied: unknown operation pulls.merge; ghgw only forwards the API operations it knows",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := append([]string{"explain", "--policy", policy, "--state-dir", dir}, tt.args...)
			if got := mustRun(t, "", args...); got != tt.want+"\n" {
				t.Errorf("explain = %q, want %q", got, tt.want+"\n")
			}
		})
	}

	t.Run("json", func(t *testing.T) {
		out := mustRun(t, "", "explain", "--policy", policy, "--state-dir", dir, "--json",
			"--user", "rpi01-agent", "--repo", "bolaum/ghgw", "--op", "push", "--default-branch", "main", "--ref", "agent/x", "--ref", "main")
		want := `{"allowed":false,"reason":"push to the default branch is not allowed; allowed branches: agent/**","grant":null,"refs":[` +
			`{"ref":"refs/heads/agent/x","allowed":false,"reason":"another ref was rejected","grant":null},` +
			`{"ref":"refs/heads/main","allowed":false,"reason":"push to the default branch is not allowed","grant":null}]}` + "\n"
		if out != want {
			t.Errorf("explain --json = %s, want %s", out, want)
		}
		out = mustRun(t, "", "explain", "--policy", policy, "--state-dir", dir, "--json",
			"--user", "rpi01-agent", "--repo", "bolaum/ghgw", "--op", "fetch")
		want = `{"allowed":true,"reason":"allowed by grant 1 of group agents","grant":{"id":1,"holder":{"kind":"group","name":"agents"}}}` + "\n"
		if out != want {
			t.Errorf("explain --json = %s, want %s", out, want)
		}
	})

	t.Run("policy from the environment", func(t *testing.T) {
		t.Setenv(policyEnv, policy)
		t.Setenv(stateDirEnv, dir)
		if got := mustRun(t, "", "explain", "--user", "rpi01-agent", "--repo", "bolaum/ghgw", "--op", "fetch"); got != "allowed by grant 1 of group agents\n" {
			t.Errorf("explain = %q", got)
		}
	})
}

func TestExplainErrors(t *testing.T) {
	dir := testEnv(t)
	tmp := t.TempDir()
	invalid := filepath.Join(tmp, "invalid.yaml")
	if err := os.WriteFile(invalid, []byte("users:\n  agent: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(tmp, "missing.yaml")
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no user", []string{"--op", "fetch"}, `required flag(s) "user" not set`},
		{"bad repository", []string{"--user", "a", "--repo", "acme", "--op", "fetch", "--policy", missing}, "repository acme: want owner/name"},
		{"missing policy", []string{"--user", "a", "--op", "fetch", "--policy", missing}, "policy file " + missing + " does not exist; write it (SPEC.md section 6) or point to it with --policy or $GHGW_POLICY"},
		{"invalid policy", []string{"--user", "a", "--op", "fetch", "--policy", invalid}, "invalid.yaml is invalid; fix it and run again:\nuser agent: no key_hash"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := append([]string{"explain", "--state-dir", dir}, tt.args...)
			if _, _, err := run(t, "", args...); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want it to contain %q", err, tt.want)
			}
		})
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("explain created the state directory before checking its flags and the policy: %v", err)
	}
}

func TestExplainRequest(t *testing.T) {
	repo, err := core.ParseRepo("bolaum/ghgw")
	if err != nil {
		t.Fatal(err)
	}
	base := explainFlags{user: "agent", repo: "bolaum/ghgw"}
	with := func(op, defBranch string, refs ...string) explainFlags {
		f := base
		f.op, f.defBranch, f.refs = op, defBranch, refs
		return f
	}
	tests := []struct {
		name    string
		flags   explainFlags
		want    core.Operation
		wantErr string
	}{
		{"fetch", with("fetch", ""), core.Fetch{}, ""},
		{"push access", with("push", ""), core.PushAccess{}, ""},
		{"push", with("push", "main", "agent/x", "refs/heads/y", ":agent/old", "refs/tags/v1", "refs/notes/x"), core.Push{
			DefaultBranch: "main",
			Updates: []core.RefUpdate{
				{Ref: "refs/heads/agent/x", Kind: core.UpdateRef},
				{Ref: "refs/heads/y", Kind: core.UpdateRef},
				{Ref: "refs/heads/agent/old", Kind: core.DeleteRef},
				{Ref: "refs/tags/v1", Kind: core.UpdateRef},
				{Ref: "refs/notes/x", Kind: core.UpdateRef},
			},
		}, ""},
		{"rest", with("pulls.create", ""), core.REST{Name: "pulls.create"}, ""},
		{"refs without default branch", with("push", "", "agent/x"), nil, "needs --default-branch"},
		{"default branch without refs", with("push", "main"), nil, "add --ref"},
		{"refs on fetch", with("fetch", "", "agent/x"), nil, "use them with --op push"},
		{"default branch on fetch", with("fetch", "main"), nil, "use them with --op push"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.flags.request()
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("request() error = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			want := core.Request{User: "agent", Repo: repo, Op: tt.want}
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Errorf("request() = %+v, %v; want %+v", got, err, want)
			}
		})
	}
}
