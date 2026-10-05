package setup

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/bolaum/ghgw/internal/store"
)

func TestGlobal(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is not installed")
	}
	key, _ := store.NewUserKey()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") != "token "+key.Reveal() {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"message": "ghgw: unknown ghgw key; run ghgw setup again with the key the admin gave you"}`)
			return
		}
		fmt.Fprint(w, `{"user": "rpi01-agent", "groups": [], "grants": []}`)
	}))
	t.Cleanup(srv.Close)
	// The test server's certificate is valid for example.com: every gateway URL reaches it.
	transport := srv.Client().Transport.(*http.Transport).Clone()
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}
	other, _ := store.NewUserKey()

	tests := []struct {
		name string
		url  string
		key  store.Secret
		// gh puts a gh in PATH; gitconfig and hosts are the global git configuration and gh's
		// hosts.yml before setup.
		gh               bool
		gitconfig, hosts string
		wantErr          string
		wantChanges      int
		wantNotes        []string
	}{
		{name: "gateway on port 443", url: "https://example.com", key: key, gh: true, wantChanges: 6},
		{name: "gh knows github.com", url: "https://example.com", key: key, gh: true, hosts: "github.com:\n    user: someone\n", wantChanges: 6,
			wantNotes: []string{"gh also knows github.com, so gh api goes to github.com unless GH_HOST=example.com is set"}},
		{name: "gateway on another port", url: "https://example.com:8443", key: key, gh: true, wantChanges: 5,
			wantNotes: []string{"gh is not set up: gh ignores the port of https://example.com:8443, so it would never send your key; serve the gateway on port 443"}},
		{name: "gh not installed", url: "https://example.com", key: key, wantChanges: 5,
			wantNotes: []string{"gh is not installed: once it is, run ghgw setup --global again"}},
		{name: "unknown key", url: "https://example.com", key: other,
			wantErr: "the gateway at https://example.com answered 401: unknown ghgw key; run ghgw setup again with the key the admin gave you"},
		{name: "another rewrite of GitHub", url: "https://example.com", key: key, gh: true,
			gitconfig: "[url \"https://old.example/\"]\n\tinsteadOf = https://github.com/\n",
			wantErr:   "git already rewrites https://github.com/ to https://old.example/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gitconfig := isolateGit(t)
			if err := os.WriteFile(gitconfig, []byte(tt.gitconfig), 0o600); err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			bin := filepath.Join(dir, "bin")
			if err := os.Mkdir(bin, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(git, filepath.Join(bin, "git")); err != nil {
				t.Fatal(err)
			}
			if tt.gh {
				if err := os.WriteFile(filepath.Join(bin, "gh"), []byte("#!/bin/sh\nexit 1\n"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("PATH", bin)
			t.Setenv("GH_CONFIG_DIR", filepath.Join(dir, "gh"))
			if tt.hosts != "" {
				if err := os.Mkdir(filepath.Join(dir, "gh"), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "gh", "hosts.yml"), []byte(tt.hosts), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			configPath := filepath.Join(dir, "ghgw", "config.yaml")

			r, err := Global(context.Background(), Options{
				ConfigPath: configPath,
				Config:     Config{URL: tt.url, Key: tt.key},
				Executable: "/usr/bin/ghgw",
				Transport:  transport,
			})
			if tt.wantErr != "" {
				if err == nil || !strings.HasPrefix(err.Error(), tt.wantErr) {
					t.Fatalf("Global() = %v, want %q", err, tt.wantErr)
				}
				// Nothing was changed.
				if _, err := os.Stat(configPath); err == nil {
					t.Error("the config was saved")
				}
				if got, _ := os.ReadFile(gitconfig); string(got) != tt.gitconfig {
					t.Errorf("git's configuration changed:\n%s", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Changes) != tt.wantChanges || slices.ContainsFunc(r.Changes, func(c Change) bool { return !c.Changed }) || !slices.Equal(r.Notes, tt.wantNotes) {
				t.Errorf("Global() = %+v, want %d changes and notes %q", r, tt.wantChanges, tt.wantNotes)
			}
			if _, err := os.Stat(filepath.Join(dir, "gh", "hosts.yml")); (err == nil) != (tt.wantChanges == 6) {
				t.Errorf("hosts.yml: %v", err)
			}
			if r.Whoami.User != "rpi01-agent" {
				t.Errorf("whoami = %+v", r.Whoami)
			}
		})
	}
}
