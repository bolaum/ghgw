package setup

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/bolaum/ghgw/internal/store"
)

func TestSetGHHost(t *testing.T) {
	key, _ := store.NewUserKey()
	entry := "ghgw.example:\n" +
		"    users:\n" +
		"        rpi01-agent:\n" +
		"            oauth_token: " + key.Reveal() + "\n" +
		"    git_protocol: https\n" +
		"    oauth_token: " + key.Reveal() + "\n" +
		"    user: rpi01-agent\n"
	github := "github.com:\n" +
		"    users:\n" +
		"        someone:\n" +
		"            oauth_token: gho_secret\n" +
		"    git_protocol: ssh\n" +
		"    oauth_token: gho_secret\n" +
		"    user: someone\n"
	tests := []struct {
		name, have  string
		want        string
		wantChanged bool
		wantOthers  []string
		wantErr     string
	}{
		{name: "no file", want: entry, wantChanged: true},
		{name: "empty file", have: "", want: entry, wantChanged: true},
		{name: "comments only", have: "# nothing yet\n", want: entry, wantChanged: true},
		{name: "another host", have: github, want: github + entry, wantChanged: true, wantOthers: []string{"github.com"}},
		{name: "already logged in", have: github + entry, want: github + entry, wantOthers: []string{"github.com"}},
		{name: "logged in as another user", have: strings.ReplaceAll(entry, "rpi01-agent", "old") + github,
			want: entry + github, wantChanged: true, wantOthers: []string{"github.com"}},
		{name: "another key", have: strings.ReplaceAll(entry, key.Reveal(), "ghgw_old"), want: entry, wantChanged: true},
		{name: "not YAML", have: "github.com: [gho_secret\n", wantErr: "is not a YAML mapping of hosts"},
		{name: "not a mapping", have: "- gho_secret\n", wantErr: "is not a YAML mapping of hosts"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "gh")
			path := filepath.Join(dir, "hosts.yml")
			if tt.name != "no file" {
				if err := os.Mkdir(dir, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(tt.have), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			c, others, err := setGHHost(dir, "ghgw.example", "rpi01-agent", key)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) || strings.Contains(err.Error(), "gho_secret") {
					t.Errorf("setGHHost() = %v, want %q without the file's tokens", err, tt.wantErr)
				}
				return
			}
			if err != nil || c.Changed != tt.wantChanged || !slices.Equal(others, tt.wantOthers) {
				t.Errorf("setGHHost() = %+v, %q, %v; want changed %v, others %q", c, others, err, tt.wantChanged, tt.wantOthers)
			}
			got, err := os.ReadFile(path)
			if err != nil || string(got) != tt.want {
				t.Errorf("hosts.yml =\n%s\nwant\n%s", got, tt.want)
			}
			if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
				t.Errorf("hosts.yml: %v, want mode 0600", err)
			}
		})
	}
}
