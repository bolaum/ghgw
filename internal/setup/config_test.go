package setup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bolaum/ghgw/internal/store"
)

func TestParseURL(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{in: "https://ghgw.example", want: "https://ghgw.example"},
		{in: "https://GHGW.example/", want: "https://ghgw.example"},
		{in: "https://ghgw.example:443", want: "https://ghgw.example"},
		{in: "https://ghgw.example:8443", want: "https://ghgw.example:8443"},
		{in: " https://ghgw.example\n", want: "https://ghgw.example"},
		{in: "http://ghgw.example"},
		{in: "ghgw.example"},
		{in: "https://ghgw.example/api"},
		{in: "https://ghgw.example?x=1"},
		{in: "https://ghgw.example#x"},
		{in: "https://x:ghgw_secret@ghgw.example"},
		{in: "https://"},
		{in: "%"},
	}
	for _, tt := range tests {
		got, err := ParseURL(tt.in)
		switch {
		case tt.want == "" && err == nil:
			t.Errorf("ParseURL(%q) = %q, want an error", tt.in, got)
		case tt.want == "" && strings.Contains(err.Error(), "secret"):
			t.Errorf("ParseURL(%q) = %v, quotes the URL", tt.in, err)
		case tt.want != "" && (err != nil || got != tt.want):
			t.Errorf("ParseURL(%q) = %q, %v; want %q", tt.in, got, err, tt.want)
		}
	}
}

func TestParseKey(t *testing.T) {
	key, _ := store.NewUserKey()
	if got, err := ParseKey(key.Reveal() + "\n"); err != nil || got.Reveal() != key.Reveal() {
		t.Errorf("ParseKey(key) = %v, want the key", err)
	}
	for _, in := range []string{"", "ghgw_abc", strings.ToUpper(key.Reveal()), "ghp_" + strings.Repeat("a", 36)} {
		if _, err := ParseKey(in); err == nil || (in != "" && strings.Contains(err.Error(), in)) {
			t.Errorf("ParseKey(%q) = %v, want an error that does not quote it", in, err)
		}
	}
}

func TestConfigFile(t *testing.T) {
	key, _ := store.NewUserKey()
	path := filepath.Join(t.TempDir(), "ghgw", "config.yaml")
	c := Config{URL: "https://ghgw.example", Key: key}

	if _, err := LoadConfig(path); err == nil || !strings.Contains(err.Error(), "no gateway is set up") {
		t.Errorf("LoadConfig(missing) = %v, want the setup hint", err)
	}
	if changed, err := saveConfig(path, c); err != nil || !changed {
		t.Fatalf("saveConfig() = %v, %v; want a new file", changed, err)
	}
	for f, want := range map[string]os.FileMode{path: 0o600, filepath.Dir(path): 0o700 | os.ModeDir} {
		if fi, err := os.Stat(f); err != nil || fi.Mode() != want {
			t.Errorf("%s: mode %v, %v; want %v", f, fi.Mode(), err, want)
		}
	}
	got, err := LoadConfig(path)
	if err != nil || got.URL != c.URL || got.Key.Reveal() != key.Reveal() {
		t.Fatalf("LoadConfig() = %+v, %v; want what was saved", got, err)
	}
	if changed, err := saveConfig(path, c); err != nil || changed {
		t.Errorf("saveConfig(same) = %v, %v; want no change", changed, err)
	}
	other, _ := store.NewUserKey()
	if changed, err := saveConfig(path, Config{URL: c.URL, Key: other}); err != nil || !changed {
		t.Errorf("saveConfig(new key) = %v, %v; want a change", changed, err)
	}

	// A file open to others is refused, and saving makes it private again.
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil || !strings.Contains(err.Error(), "run chmod 600 "+path) {
		t.Errorf("LoadConfig(0640) = %v, want the chmod to run", err)
	}
	if changed, err := saveConfig(path, Config{URL: c.URL, Key: other}); err != nil || !changed {
		t.Errorf("saveConfig(0640) = %v, %v; want a change", changed, err)
	}
	if _, err := LoadConfig(path); err != nil {
		t.Errorf("LoadConfig() after saving = %v", err)
	}

	for name, content := range map[string]string{
		"not YAML":      "url: [" + key.Reveal(),
		"unknown field": "url: https://ghgw.example\nkey: " + key.Reveal() + "\ntoken: " + key.Reveal() + "\n",
		"bad URL":       "url: http://ghgw.example\nkey: " + key.Reveal() + "\n",
		"bad key":       "url: https://ghgw.example\nkey: " + key.Reveal()[:20] + "\n",
		"no key":        "url: https://ghgw.example\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := LoadConfig(path)
			if err == nil || !strings.Contains(err.Error(), "is malformed; run ghgw setup --global again") || strings.Contains(err.Error(), key.Reveal()[:20]) {
				t.Errorf("LoadConfig() = %v, want malformed without the key", err)
			}
		})
	}
}
