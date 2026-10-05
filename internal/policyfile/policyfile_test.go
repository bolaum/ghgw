package policyfile

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bolaum/ghgw/internal/core"
)

const (
	hashA = "sha256:" + "aa00000000000000000000000000000000000000000000000000000000000000"
	hashB = "sha256:" + "bb00000000000000000000000000000000000000000000000000000000000000"
)

// specPolicy is the policy of SPEC.md section 6 with the key hashes and grant IDs a file needs.
const specPolicy = `
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
    key_hash: ` + hashA + `
    groups: [agents]
  devct01-agent:
    key_hash: ` + hashB + `
    groups: [agents]
    grants:
      - id: 2
        repos: ["acme/ml-lab"]
        access: write
        push: ["agent/**"]
        api: pr
`

func TestParseSpecPolicy(t *testing.T) {
	pf, err := Parse([]byte(specPolicy))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	p, err := pf.Policy([]string{"bolaum", "acme"})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		user, repo string
		op         core.Operation
		want       string
	}{
		{"rpi01-agent", "bolaum/ghgw", core.PushAccess{}, "allowed by grant 1 of group agents"},
		{"devct01-agent", "acme/ml-lab", core.Fetch{}, "allowed by grant 2 of user devct01-agent"},
		{"rpi01-agent", "acme/ml-lab", core.Fetch{}, "denied: rpi01-agent cannot access acme/ml-lab. Repositories allowed: bolaum/*"},
		{"devct01-agent", "bolaum/ghgw", core.Push{DefaultBranch: "main", Updates: []core.RefUpdate{
			{Ref: "refs/heads/agent/x", Kind: core.UpdateRef},
		}}, "allowed by grant 1 of group agents\n  refs/heads/agent/x: allowed by grant 1 of group agents"},
	}
	for _, tt := range tests {
		repo, err := core.ParseRepo(tt.repo)
		if err != nil {
			t.Fatal(err)
		}
		if got := p.Decide(core.Request{User: tt.user, Repo: repo, Op: tt.op}).String(); got != tt.want {
			t.Errorf("Decide(%s, %s) = %q, want %q", tt.user, tt.repo, got, tt.want)
		}
	}
}

func TestUserByKeyHash(t *testing.T) {
	pf, err := Parse([]byte(specPolicy))
	if err != nil {
		t.Fatal(err)
	}
	hash := func(s string) []byte {
		b, err := hex.DecodeString(strings.TrimPrefix(s, keyHashPrefix))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	sameSelector := hash(hashA)
	sameSelector[len(sameSelector)-1] ^= 1
	tests := []struct {
		name     string
		hash     []byte
		wantUser string
	}{
		{name: "first user", hash: hash(hashA), wantUser: "rpi01-agent"},
		{name: "second user", hash: hash(hashB), wantUser: "devct01-agent"},
		{name: "same selector, other hash", hash: sameSelector},
		{name: "unknown", hash: make([]byte, 32)},
		{name: "selector only", hash: hash(hashA)[:selectorBytes]},
		{name: "empty"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, ok := pf.UserByKeyHash(tt.hash)
			if user != tt.wantUser || ok != (tt.wantUser != "") {
				t.Errorf("UserByKeyHash() = %q, %v, want %q", user, ok, tt.wantUser)
			}
		})
	}
}

func TestParseEmpty(t *testing.T) {
	for _, data := range []string{"", "# nothing yet\n", "{}"} {
		pf, err := Parse([]byte(data))
		if err != nil {
			t.Errorf("Parse(%q) error = %v", data, err)
			continue
		}
		if len(pf.State.Users) != 0 || len(pf.State.Groups) != 0 || len(pf.State.Grants) != 0 {
			t.Errorf("Parse(%q) = %+v, want an empty policy", data, pf.State)
		}
	}
}

func TestParseErrors(t *testing.T) {
	user := func(body string) string { return "users:\n  agent:\n    key_hash: " + hashA + "\n" + body }
	tests := []struct {
		name string
		data string
		want []string // each must be in the error
	}{
		{
			name: "syntax",
			data: "users: [",
			want: []string{"line 1:"},
		},
		{
			name: "unknown field",
			data: user("    grants:\n      - id: 1\n        repos: [a/b]\n        acess: read\n"),
			want: []string{"line 7: field acess not found in type policyfile.grant"},
		},
		{
			name: "two documents",
			data: "users: {}\n---\ngroups: {}\n",
			want: []string{"more than one YAML document"},
		},
		{
			name: "no key hash",
			data: "users:\n  agent:\n    groups: []\n",
			want: []string{"user agent: no key_hash; create a key with ghgw key new"},
		},
		{
			name: "key instead of hash",
			data: "users:\n  agent:\n    key_hash: ghgw_" + strings.Repeat("a", 64) + "\n",
			want: []string{"user agent: key_hash holds a ghgw key, not its hash"},
		},
		{
			name: "malformed hash",
			data: "users:\n  agent:\n    key_hash: sha256:abc\n",
			want: []string{"user agent: key_hash must be sha256: and 64 hex characters"},
		},
		{
			name: "hash without prefix",
			data: "users:\n  agent:\n    key_hash: " + strings.TrimPrefix(hashA, "sha256:") + "\n",
			want: []string{"key_hash must be sha256:"},
		},
		{
			name: "shared hash",
			data: "users:\n  a1:\n    key_hash: " + hashA + "\n  a2:\n    key_hash: " + hashA + "\n",
			want: []string{"users a1 and a2 have the same key_hash"},
		},
		{
			name: "undefined group",
			data: user("    groups: [agents]\n"),
			want: []string{"user agent: group agents is not defined; add it under groups"},
		},
		{
			name: "grant without id",
			data: user("    grants:\n      - repos: [a/b]\n        access: read\n"),
			want: []string{"user agent: grant 1 in the list has no id"},
		},
		{
			name: "duplicate id",
			data: user("    grants:\n      - {id: 3, repos: [a/b], access: read}\n") +
				"groups:\n  g:\n    grants:\n      - {id: 3, repos: [a/c], access: read}\n",
			want: []string{"grant 3 is defined twice"},
		},
		{
			name: "bad repository pattern",
			data: user("    grants:\n      - {id: 1, repos: ['*/x'], access: read}\n"),
			want: []string{"grant 1 of user agent: repository pattern */x: the owner cannot contain '*'"},
		},
		{
			name: "bad push pattern",
			data: user("    grants:\n      - {id: 1, repos: [a/b], access: write, push: ['refs/heads/x']}\n"),
			want: []string{"grant 1 of user agent: branch pattern"},
		},
		{
			name: "push with read access",
			data: user("    grants:\n      - {id: 1, repos: [a/b], access: read, push: [x]}\n"),
			want: []string{"grant 1 of user agent: push branches need access write"},
		},
		{
			name: "every problem of a grant",
			data: user("    grants:\n      - {id: 1, repos: ['*/x', 'a/**'], access: wrte, push: ['refs/heads/x'], api: wrong}\n"),
			want: []string{
				"grant 1 of user agent: repository pattern */x",
				"grant 1 of user agent: repository pattern a/**",
				"grant 1 of user agent: branch pattern refs/heads/x",
				"grant 1 of user agent: access must be read or write, not wrte",
				"grant 1 of user agent: api must be read or pr (or empty for none), not wrong",
			},
		},
		{
			name: "grant without id and with other problems",
			data: user("    grants:\n      - {repos: ['*/x'], access: read}\n"),
			want: []string{"user agent: grant 1 in the list has no id", "grant 0 of user agent: repository pattern */x"},
		},
		{
			name: "negative id",
			data: user("    grants:\n      - {id: -2, repos: [a/b], access: read}\n"),
			want: []string{"user agent: grant 1 in the list has id -2; give it a positive one"},
		},
		{
			name: "key hash that is not a string",
			data: "users:\n  agent:\n    key_hash: [" + hashA + "]\n",
			want: []string{"user agent: key_hash must be sha256: and 64 hex characters"},
		},
		{
			name: "null key hash",
			data: "users:\n  agent:\n    key_hash: ~\n",
			want: []string{"user agent: no key_hash"},
		},
		{
			name: "bad access and api",
			data: user("    grants:\n      - {id: 1, repos: [a/b], access: wrte}\n      - {id: 2, repos: [a/b], access: read, api: none}\n"),
			want: []string{"access must be read or write, not wrte", "api must be read or pr (or empty for none), not none"},
		},
		{
			name: "bad user name",
			data: "users:\n  Agent:\n    key_hash: " + hashA + "\n",
			want: []string{"user name Agent must be 1 to 64 lowercase letters"},
		},
		{
			name: "every problem at once",
			data: "users:\n  a1:\n    groups: [nope]\n  a2:\n    key_hash: sha256:00\n",
			want: []string{"user a1: no key_hash", "user a1: group nope is not defined", "user a2: key_hash must be"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.data))
			if err == nil {
				t.Fatal("Parse() error = nil")
			}
			for _, w := range tt.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("Parse() error = %q, want it to contain %q", err, w)
				}
			}
			if strings.Contains(err.Error(), "yaml:") {
				t.Errorf("Parse() error = %q, want no yaml: prefix", err)
			}
		})
	}
}

func TestParseErrorsDoNotQuoteKeys(t *testing.T) {
	key := "ghgw_" + strings.Repeat("c", 64)
	for _, value := range []string{
		key, "sha256:" + key, "github_pat_" + strings.Repeat("x", 40),
		"!!int " + key, "!!bool " + key, "!!timestamp " + key, "!!float " + key, "!!binary " + key,
		"[" + key + "]", "{k: " + key + "}", "!!int " + hashA, "*" + key,
	} {
		_, err := Parse([]byte("users:\n  agent:\n    key_hash: " + value + "\n"))
		if err == nil {
			t.Fatalf("Parse(key_hash: %s...) error = nil", value[:8])
		}
		if strings.Contains(err.Error(), value) || strings.Contains(err.Error(), strings.Repeat("c", 64)) {
			t.Errorf("Parse() error quotes the key_hash value: %q", err)
		}
	}
	// YAML errors quote values outside key_hash too: a key pasted in the wrong field is redacted.
	_, err := Parse([]byte("users:\n  agent:\n    key_hash: " + hashA + "\n    disabled: " + key + "\n"))
	if err == nil || strings.Contains(err.Error(), strings.Repeat("c", 64)) || !strings.Contains(err.Error(), "[redacted]") {
		t.Errorf("Parse(disabled: <key>) error = %v, want the key redacted", err)
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	write := func(name, data string, mode os.FileMode) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(data), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil { // the umask may have cleared bits
			t.Fatal(err)
		}
		return path
	}
	if _, err := Load(write("ok.yaml", specPolicy, 0o644)); err != nil {
		t.Errorf("Load(mode 0644) error = %v", err)
	}
	tests := []struct {
		name string
		path string
		want string
	}{
		{"missing", filepath.Join(dir, "missing.yaml"), "no such file"},
		{"directory", dir, "is not a regular file"},
		{"group writable", write("gw.yaml", specPolicy, 0o664), "writable by group or others (mode 0664)"},
		{"other writable", write("ow.yaml", specPolicy, 0o602), "run chmod go-w"},
		{"too large", write("big.yaml", "#"+string(bytes.Repeat([]byte("x"), MaxSize)), 0o600), "larger than"},
		{"invalid", write("bad.yaml", "users:\n  agent: {}\n", 0o600), "bad.yaml is invalid; fix it and run again:\nuser agent: no key_hash"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(tt.path)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Load() error = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

// TestSpecExample keeps the policy file example of SPEC.md section 6 valid.
func TestSpecExample(t *testing.T) {
	spec, err := os.ReadFile("../../SPEC.md")
	if err != nil {
		t.Fatal(err)
	}
	_, section, _ := strings.Cut(string(spec), "\n## 6. Policy\n")
	_, example, ok := strings.Cut(section, "```yaml\n")
	example, _, ok2 := strings.Cut(example, "```")
	if !ok || !ok2 {
		t.Fatal("SPEC.md section 6 has no yaml example")
	}
	pf, err := Parse([]byte(example))
	if err != nil {
		t.Fatalf("Parse(SPEC.md example) error = %v", err)
	}
	if len(pf.State.Users) != 2 || len(pf.State.Groups) != 1 || len(pf.State.Grants) != 2 {
		t.Errorf("SPEC.md example = %+v, want 2 users, 1 group and 2 grants", pf.State)
	}
}
