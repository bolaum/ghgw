package core

import (
	"strings"
	"testing"
)

func TestRepoGlob(t *testing.T) {
	tests := []struct {
		glob    string
		wantErr string
		match   []string
		noMatch []string
	}{
		{
			glob:    "bolaum/ghgw",
			match:   []string{"bolaum/ghgw", "Bolaum/GHGW", "BOLAUM/ghgw"},
			noMatch: []string{"bolaum/ghgw2", "bolaum/gh", "acme/ghgw", "bolaum2/ghgw"},
		},
		{
			glob:    "bolaum/*",
			match:   []string{"bolaum/a", "Bolaum/Anything.else", "bolaum/.github"},
			noMatch: []string{"acme/a", "bolaumx/a", "xbolaum/a"},
		},
		{
			glob:    "acme/agent-*",
			match:   []string{"acme/agent-", "acme/agent-1", "ACME/Agent-Lab"},
			noMatch: []string{"acme/agent", "acme/xagent-1", "acme/lab"},
		},
		{
			glob:    "acme/*-lab",
			match:   []string{"acme/ml-lab", "acme/-lab"},
			noMatch: []string{"acme/ml-lab2", "acme/lab"},
		},
		{
			// '.' is literal, not a regexp wildcard.
			glob:    "acme/a.b",
			match:   []string{"acme/a.b"},
			noMatch: []string{"acme/axb"},
		},
		{glob: "*/*", wantErr: "owner cannot contain '*'"},
		{glob: "bol*/repo", wantErr: "owner cannot contain '*'"},
		{glob: "bolaum/**", wantErr: "not '**'"},
		{glob: "bolaum", wantErr: "want owner/name"},
		{glob: "bolaum/", wantErr: "name must be"},
		{glob: "bolaum/a/b", wantErr: "name must be"},
		{glob: "bolaum/..", wantErr: "name must be"},
		{glob: "bolaum/a?", wantErr: "name must be"},
		{glob: "bolaum/[ab]", wantErr: "name must be"},
		{glob: "Bad Owner/x", wantErr: "owner"},
	}
	for _, tt := range tests {
		t.Run(tt.glob, func(t *testing.T) {
			g, err := ParseRepoGlob(tt.glob)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("ParseRepoGlob(%q) error = %v, want it to contain %q", tt.glob, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseRepoGlob(%q) error = %v", tt.glob, err)
			}
			if g.String() != tt.glob {
				t.Errorf("String() = %q, want %q", g.String(), tt.glob)
			}
			for _, r := range tt.match {
				if !g.Match(mustRepo(t, r)) {
					t.Errorf("%q does not match %q, want a match", tt.glob, r)
				}
			}
			for _, r := range tt.noMatch {
				if g.Match(mustRepo(t, r)) {
					t.Errorf("%q matches %q, want no match", tt.glob, r)
				}
			}
		})
	}

	if (RepoGlob{}).Match(mustRepo(t, "bolaum/ghgw")) {
		t.Error("the zero RepoGlob matches, want no match")
	}
}

func TestBranchGlob(t *testing.T) {
	tests := []struct {
		glob    string
		wantErr string
		match   []string
		noMatch []string
	}{
		{
			glob:    "main",
			match:   []string{"main"},
			noMatch: []string{"Main", "main2", "x/main"},
		},
		{
			glob:    "agent/*",
			match:   []string{"agent/x", "agent/feature-1"},
			noMatch: []string{"agent/x/y", "agent", "Agent/x", "other/agent/x"},
		},
		{
			glob:    "agent/**",
			match:   []string{"agent/x", "agent/x/y", "agent/a/b/c"},
			noMatch: []string{"agent", "agentx/y", "Agent/x", "x/agent/y"},
		},
		{
			glob:    "**/wip",
			match:   []string{"a/wip", "a/b/wip"},
			noMatch: []string{"wip", "a/wip2"},
		},
		{
			glob:    "*",
			match:   []string{"main", "feature"},
			noMatch: []string{"agent/x"},
		},
		{
			glob:  "**",
			match: []string{"main", "agent/x/y"},
		},
		{
			glob:    "feat*",
			match:   []string{"feat", "feature"},
			noMatch: []string{"feature/x"},
		},
		{
			glob:    "feat**",
			match:   []string{"feat", "feature/x"},
			noMatch: []string{"xfeat"},
		},
		{
			// '.' and '+' are literal.
			glob:    "v1.x+y",
			match:   []string{"v1.x+y"},
			noMatch: []string{"v1axxy"},
		},
		{glob: "", wantErr: "empty"},
		{glob: "refs/heads/agent/*", wantErr: "without refs/heads/"},
		{glob: "agent/***", wantErr: "three stars"},
		{glob: "agent/", wantErr: "cannot end with '/'"},
		{glob: "agent//x", wantErr: `"//"`},
		{glob: "agent/x.", wantErr: "cannot end with '.'"},
		{glob: "a..b", wantErr: `".."`},
		{glob: "a@{b", wantErr: `"@{"`},
		{glob: "a b", wantErr: `' '`},
		{glob: "a?", wantErr: `'?'`},
		{glob: "a[b]", wantErr: `'['`},
		{glob: "a~1", wantErr: `'~'`},
		{glob: "a^", wantErr: `'^'`},
		{glob: "a:b", wantErr: `':'`},
		{glob: `a\b`, wantErr: `'\\'`},
		{glob: "a\tb", wantErr: `'\t'`},
		{glob: ".hidden/*", wantErr: "start with '.'"},
		{glob: "x/*.lock", wantErr: `".lock"`},
		{glob: "\xff", wantErr: "UTF-8"},
	}
	for _, tt := range tests {
		t.Run(tt.glob, func(t *testing.T) {
			g, err := ParseBranchGlob(tt.glob)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("ParseBranchGlob(%q) error = %v, want it to contain %q", tt.glob, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseBranchGlob(%q) error = %v", tt.glob, err)
			}
			if g.String() != tt.glob {
				t.Errorf("String() = %q, want %q", g.String(), tt.glob)
			}
			for _, b := range tt.match {
				if !g.Match(b) {
					t.Errorf("%q does not match %q, want a match", tt.glob, b)
				}
			}
			for _, b := range tt.noMatch {
				if g.Match(b) {
					t.Errorf("%q matches %q, want no match", tt.glob, b)
				}
			}
		})
	}

	if (BranchGlob{}).Match("main") {
		t.Error("the zero BranchGlob matches, want no match")
	}
}
