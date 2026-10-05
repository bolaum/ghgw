package main

import (
	"path/filepath"
	"testing"
)

func TestDefaultPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	tests := []struct {
		name, env, xdg, want string
	}{
		{"variable", "/srv/ghgw", "/xdg", "/srv/ghgw"},
		{"xdg", "", "/xdg", "/xdg/ghgw"},
		{"relative xdg is ignored", "", "xdg", filepath.Join(home, ".local/state/ghgw")},
		{"home", "", "", filepath.Join(home, ".local/state/ghgw")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(stateDirEnv, tt.env)
			t.Setenv("XDG_STATE_HOME", tt.xdg)
			if got, err := defaultPath(stateDirEnv, "XDG_STATE_HOME", ".local/state", "ghgw"); err != nil || got != tt.want {
				t.Errorf("defaultPath() = %q, %v; want %q", got, err, tt.want)
			}
		})
	}
}
