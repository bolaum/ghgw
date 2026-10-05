package core

import (
	"strings"
	"testing"
)

func mustRepo(t *testing.T, s string) Repo {
	t.Helper()
	r, err := ParseRepo(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestParseRepo(t *testing.T) {
	tests := []struct {
		in      string
		wantErr string
	}{
		{in: "bolaum/ghgw"},
		{in: "Bolaum/GHGW"},
		{in: "my-org/my.repo_2"},
		{in: "user_emu/repo"},
		{in: "bolaum/.github"},
		{in: "bolaum", wantErr: "want owner/name"},
		{in: "", wantErr: "want owner/name"},
		{in: "/repo", wantErr: "owner"},
		{in: "bolaum/", wantErr: "name must be"},
		{in: "-bolaum/repo", wantErr: "owner"},
		{in: "bolaum/a/b", wantErr: "name must be"},
		{in: "bolaum/..", wantErr: "name must be"},
		{in: "bolaum/.", wantErr: "name must be"},
		{in: "../repo", wantErr: "owner"},
		{in: "bolaum/a%2fb", wantErr: "name must be"},
		{in: "bolaum/repo name", wantErr: "name must be"},
		{in: "bolaum/" + strings.Repeat("a", 101), wantErr: "name must be"},
		{in: "bolaum/" + strings.Repeat("a", 100)},
		{in: strings.Repeat("o", 100) + "/x"},
		{in: strings.Repeat("o", 101) + "/x", wantErr: "owner"},
		// The transports treat ".git" as optional, so names ending in it would be ambiguous.
		{in: "bolaum/x.git", wantErr: "without the .git suffix"},
		{in: "bolaum/x.GIT", wantErr: "without the .git suffix"},
		{in: "bolaum/.git", wantErr: "without the .git suffix"},
		{in: "bolaum/x.github"},
		// GitHub serves the wiki of x as x.wiki, which a grant on x.wiki must not reach.
		{in: "bolaum/x.wiki", wantErr: "names ending in .wiki are GitHub wikis"},
		{in: "bolaum/x.WIKI", wantErr: "names ending in .wiki are GitHub wikis"},
		{in: "bolaum/x.wikis"},
		// Look-alikes, encodings and separators never reach policy matching.
		{in: "bolaum/K", wantErr: "name must be"},      // Kelvin sign, folds to k
		{in: "Kcme/x", wantErr: "owner"},               // Kelvin sign, folds to k
		{in: "bolaum/ſecret", wantErr: "name must be"}, // long s, folds to s
		{in: "ｂolaum/x", wantErr: "owner"},             // full-width b
		{in: "bolaum/ｘ", wantErr: "name must be"},      // full-width x
		{in: "bolaum/a%2Fb", wantErr: "name must be"},
		{in: "bolaum/a%252Fb", wantErr: "name must be"},
		{in: "bolaum/%2e%2e", wantErr: "name must be"},
		{in: "bolaum%2Fx/y", wantErr: "owner"},
		{in: `bolaum/a\b`, wantErr: "name must be"},
		{in: `bolaum\x/y`, wantErr: "owner"},
		{in: "bolaum/a\x00", wantErr: "name must be"},
		{in: "bolaum/a\r\nb", wantErr: "name must be"},
		{in: "bolaum\n/x", wantErr: "owner"},
		{in: "bolaum//x", wantErr: "name must be"},
		{in: "bolaum/x/", wantErr: "name must be"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			r, err := ParseRepo(tt.in)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("ParseRepo(%q) error = %v, want it to contain %q", tt.in, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseRepo(%q) error = %v", tt.in, err)
			}
			if r.String() != tt.in {
				t.Errorf("String() = %q, want %q (case is kept)", r.String(), tt.in)
			}
		})
	}
}

func TestZeroRepo(t *testing.T) {
	var r Repo
	if !r.IsZero() || r.String() != "" || r.Owner() != "" {
		t.Errorf("zero Repo: IsZero() = %v, String() = %q, Owner() = %q; want true, \"\", \"\"", r.IsZero(), r.String(), r.Owner())
	}
	if mustRepo(t, "bolaum/ghgw").IsZero() {
		t.Error("bolaum/ghgw is zero")
	}
}
