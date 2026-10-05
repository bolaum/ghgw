package setup

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// isolateGit points git config --global at a new file and keeps the system's configuration out.
func isolateGit(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	path := filepath.Join(t.TempDir(), "gitconfig")
	t.Setenv("GIT_CONFIG_GLOBAL", path)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	return path
}

func TestGitConfig(t *testing.T) {
	ctx := context.Background()
	path := isolateGit(t)
	git, err := newGitConfig()
	if err != nil {
		t.Fatal(err)
	}
	const base = "https://ghgw.example/"
	// The user's own settings: a helper for every URL and a rewrite of something else.
	stored := filepath.Join(t.TempDir(), "credentials")
	for _, args := range [][]string{
		{"--add", "credential.helper", "store --file=" + stored},
		{"--add", "url.https://mirror.example/.insteadOf", "https://gitlab.com/"},
		{"--add", "url." + base + ".insteadOf", "https://github.com/"},
	} {
		if _, err := git.run(ctx, args...); err != nil {
			t.Fatal(err)
		}
	}

	for i, wantChanged := range []bool{true, false} {
		bases, err := git.insteadOfs(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := checkRewrites(bases, base); err != nil {
			t.Fatalf("checkRewrites() = %v", err)
		}
		rewrites, err := git.setRewrites(ctx, bases, base)
		if err != nil {
			t.Fatal(err)
		}
		// https://github.com/ was there before the first run.
		if len(rewrites) != 3 || rewrites[0].Changed || rewrites[1].Changed != wantChanged || rewrites[2].Changed != wantChanged {
			t.Errorf("run %d: setRewrites() = %+v", i, rewrites)
		}
		helper, err := git.setHelper(ctx, "https://ghgw.example", HelperCommand("/opt/ghgw tools/ghgw"))
		if err != nil || helper.Changed != wantChanged {
			t.Errorf("run %d: setHelper() = %+v, %v; want changed %v", i, helper, err, wantChanged)
		}
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := `[credential]
	helper = store --file=` + stored + `
[url "https://mirror.example/"]
	insteadOf = https://gitlab.com/
[url "https://ghgw.example/"]
	insteadOf = https://github.com/
	insteadOf = git@github.com:
	insteadOf = ssh://git@github.com/
[credential "https://ghgw.example"]
	helper = 
	helper = !'/opt/ghgw tools/ghgw' credential
`
	if string(got) != want {
		t.Errorf("git config =\n%s\nwant\n%s", got, want)
	}

	// git tells the gateway's helper only to store the key: the user's helper never sees it.
	cmd := exec.Command("git", "credential", "approve")
	cmd.Stdin = strings.NewReader("protocol=https\nhost=ghgw.example\nusername=ghgw\npassword=ghgw_x\n\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git credential approve: %v\n%s", err, out)
	}
	if _, err := os.Stat(stored); err == nil {
		t.Error("the user's credential helper stored the gateway's key")
	}

	// Another helper set for the gateway is replaced.
	if _, err := git.run(ctx, "--add", "credential.https://ghgw.example.helper", "cache"); err != nil {
		t.Fatal(err)
	}
	if helper, err := git.setHelper(ctx, "https://ghgw.example", HelperCommand("/usr/bin/ghgw")); err != nil || !helper.Changed {
		t.Errorf("setHelper() = %+v, %v; want a change", helper, err)
	}
	if out, err := git.run(ctx, "--get-all", "credential.https://ghgw.example.helper"); err != nil || out != "\n!/usr/bin/ghgw credential\n" {
		t.Errorf("the gateway's helpers = %q, %v", out, err)
	}
}

func TestCheckRewrites(t *testing.T) {
	const base = "https://ghgw.example/"
	tests := []struct {
		name    string
		bases   map[string][]string
		wantErr string
	}{
		{name: "none"},
		{name: "ours", bases: map[string][]string{base: {"https://github.com/", "git@github.com:"}}},
		{name: "other prefixes", bases: map[string][]string{"https://mirror.example/": {"https://gitlab.com/"}}},
		{name: "another gateway", bases: map[string][]string{"https://old.example/": {"git@github.com:"}},
			wantErr: "git already rewrites git@github.com: to https://old.example/; remove that with\n" +
				"  git config --global --fixed-value --unset url.https://old.example/.insteadOf git@github.com:\n" +
				"then run ghgw setup --global again"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkRewrites(tt.bases, base)
			if (err == nil) != (tt.wantErr == "") || (err != nil && err.Error() != tt.wantErr) {
				t.Errorf("checkRewrites() = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestHelperCommand(t *testing.T) {
	for exe, want := range map[string]string{
		"/usr/local/bin/ghgw":  "!/usr/local/bin/ghgw credential",
		"/home/a b/ghgw":       "!'/home/a b/ghgw' credential",
		"/home/it's/ghgw":      `!'/home/it'\''s/ghgw' credential`,
		"/home/$HOME/ghgw":     "!'/home/$HOME/ghgw' credential",
		"/opt/ghgw-1.0+x/ghgw": "!/opt/ghgw-1.0+x/ghgw credential",
	} {
		if got := HelperCommand(exe); got != want {
			t.Errorf("HelperCommand(%q) = %q, want %q", exe, got, want)
		}
	}
	if strings.Contains(HelperCommand("/a'b"), "a'b") {
		t.Error("a quote is not escaped")
	}
}
