package core

import (
	"slices"
	"strings"
	"testing"
)

// grant builds a grant from strings; holder is "user NAME" or "group NAME", push and api may be
// empty.
func grant(t *testing.T, id int, holder string, repos []string, access Access, push []string, api Preset) Grant {
	t.Helper()
	kind, name, _ := strings.Cut(holder, " ")
	g := Grant{ID: id, Holder: Holder{Name: name}, Access: access, API: api}
	switch kind {
	case "user":
		g.Holder.Kind = HolderUser
	case "group":
		g.Holder.Kind = HolderGroup
	}
	for _, r := range repos {
		rg, err := ParseRepoGlob(r)
		if err != nil {
			t.Fatal(err)
		}
		g.Repos = append(g.Repos, rg)
	}
	for _, b := range push {
		bg, err := ParseBranchGlob(b)
		if err != nil {
			t.Fatal(err)
		}
		g.Push = append(g.Push, bg)
	}
	return g
}

// checkErrorLines checks that err has one line per entry of want, each starting with it, in order.
func checkErrorLines(t *testing.T, err error, want []string) {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want %q", want)
	}
	got := strings.Split(err.Error(), "\n")
	ok := len(got) == len(want)
	for i := 0; ok && i < len(got); i++ {
		ok = strings.HasPrefix(got[i], want[i])
	}
	if !ok {
		t.Errorf("errors:\n%s\nwant lines starting with:\n%s", err, strings.Join(want, "\n"))
	}
}

func TestNewPolicyValidation(t *testing.T) {
	users := []User{{Name: "rpi01-agent"}, {Name: "devct01-agent"}}
	groups := []Group{{Name: "agents", Members: []string{"rpi01-agent", "devct01-agent"}}}
	bolaum := []string{"bolaum/*"}

	tests := []struct {
		name    string
		state   func(t *testing.T) State
		wantErr []string
	}{
		{
			name: "section 6 example",
			state: func(t *testing.T) State {
				return State{
					Users:  users,
					Groups: groups,
					Grants: []Grant{
						grant(t, 1, "group agents", bolaum, AccessWrite, []string{"agent/**"}, PresetPR),
						grant(t, 2, "user devct01-agent", []string{"acme/ml-lab"}, AccessWrite, []string{"agent/**"}, PresetPR),
					},
					Owners: []string{"bolaum", "acme"},
				}
			},
		},
		{
			name: "read access without push and api",
			state: func(t *testing.T) State {
				return State{Users: users, Grants: []Grant{grant(t, 1, "user rpi01-agent", bolaum, AccessRead, nil, PresetNone)}}
			},
		},
		{
			name:  "empty",
			state: func(*testing.T) State { return State{} },
		},
		{
			name: "invalid names",
			state: func(*testing.T) State {
				return State{
					Users:  []User{{Name: "Agent"}, {Name: ""}},
					Groups: []Group{{Name: "my group"}},
					Owners: []string{"-acme"},
				}
			},
			wantErr: []string{`user name Agent `, `user name ""`, `group name my group `, `owner -acme `},
		},
		{
			name: "duplicates",
			state: func(t *testing.T) State {
				return State{
					Users:  []User{{Name: "a"}, {Name: "a"}},
					Groups: []Group{{Name: "g", Members: []string{"a", "a"}}, {Name: "g"}},
					Grants: []Grant{
						grant(t, 1, "user a", bolaum, AccessRead, nil, ""),
						grant(t, 1, "group g", bolaum, AccessRead, nil, ""),
					},
					Owners: []string{"acme", "ACME"},
				}
			},
			wantErr: []string{
				"user a is defined twice",
				"group g: member a is listed twice",
				"group g is defined twice",
				"grant 1 is defined twice",
				"owner ACME is defined twice",
			},
		},
		{
			name: "unknown member",
			state: func(*testing.T) State {
				return State{Users: users, Groups: []Group{{Name: "agents", Members: []string{"ghost"}}}}
			},
			wantErr: []string{"group agents: member ghost is not a user; create the user first"},
		},
		{
			name: "grant problems",
			state: func(t *testing.T) State {
				noRepos := grant(t, 3, "user rpi01-agent", nil, AccessRead, nil, "")
				zeroRepo := grant(t, 4, "user rpi01-agent", nil, AccessRead, nil, "")
				zeroRepo.Repos = []RepoGlob{{}}
				zeroPush := grant(t, 9, "user rpi01-agent", bolaum, AccessWrite, nil, "")
				zeroPush.Push = []BranchGlob{{}}
				noKind := grant(t, 10, "user rpi01-agent", bolaum, AccessRead, nil, "")
				noKind.Holder.Kind = 0
				tooManyRepos := grant(t, 11, "user rpi01-agent", slices.Repeat(bolaum, MaxGrantPatterns+1), AccessRead, nil, "")
				tooManyPush := grant(t, 12, "user rpi01-agent", bolaum, AccessWrite, slices.Repeat([]string{"agent/**"}, MaxGrantPatterns+1), "")
				everything := grant(t, 13, "user ghost", nil, "wrte", []string{"agent/**"}, "wrong")
				everything.Push = append(everything.Push, BranchGlob{})
				return State{
					Users:  users,
					Groups: groups,
					Grants: []Grant{
						grant(t, 0, "user rpi01-agent", bolaum, AccessRead, nil, ""),
						grant(t, 1, "user ghost", bolaum, AccessRead, nil, ""),
						grant(t, 2, "group ghosts", bolaum, AccessRead, nil, ""),
						noRepos,
						zeroRepo,
						grant(t, 5, "user rpi01-agent", bolaum, "admin", nil, ""),
						grant(t, 6, "user rpi01-agent", bolaum, "", nil, ""),
						grant(t, 7, "user rpi01-agent", bolaum, AccessRead, []string{"agent/**"}, ""),
						grant(t, 8, "user rpi01-agent", bolaum, AccessRead, nil, "admin"),
						zeroPush,
						noKind,
						tooManyRepos,
						tooManyPush,
						everything,
					},
				}
			},
			wantErr: []string{
				"grant 0: the ID must be positive",
				"grant 1 of user ghost: user ghost does not exist; create it first",
				"grant 2 of group ghosts: group ghosts does not exist; create it first",
				"grant 3 of user rpi01-agent: needs at least one repository pattern",
				"grant 4 of user rpi01-agent: has an empty repository pattern",
				"grant 5 of user rpi01-agent: access must be read or write, not admin",
				`grant 6 of user rpi01-agent: access must be read or write, not ""`,
				"grant 7 of user rpi01-agent: push branches need access write",
				"grant 8 of user rpi01-agent: api must be read or pr (or empty for none), not admin",
				"grant 9 of user rpi01-agent: has an empty push pattern",
				"grant 10 of holder rpi01-agent: the holder must be a user or a group",
				"grant 11 of user rpi01-agent: has 101 repository patterns; a grant has at most 100",
				"grant 12 of user rpi01-agent: has 101 push patterns; a grant has at most 100",
				"grant 13 of user ghost: user ghost does not exist; create it first",
				"grant 13 of user ghost: needs at least one repository pattern",
				"grant 13 of user ghost: access must be read or write, not wrte",
				"grant 13 of user ghost: api must be read or pr (or empty for none), not wrong",
				"grant 13 of user ghost: has an empty push pattern",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := NewPolicy(tt.state(t), nil)
			if len(tt.wantErr) == 0 {
				if err != nil || p == nil {
					t.Fatalf("NewPolicy() = %v, %v; want a policy", p, err)
				}
				return
			}
			checkErrorLines(t, err, tt.wantErr)
			if p != nil {
				t.Errorf("NewPolicy() returned a policy with an error")
			}
		})
	}
}

func TestParseGrant(t *testing.T) {
	holder := Holder{Kind: HolderGroup, Name: "agents"}
	tests := []struct {
		name         string
		repos, push  []string
		access       Access
		api          Preset
		wantErr      []string
		repoN, pushN int
	}{
		{name: "valid", repos: []string{"bolaum/*", "acme/app"}, push: []string{"agent/**"}, access: AccessWrite, api: PresetPR, repoN: 2, pushN: 1},
		{
			name:  "every problem",
			repos: []string{"*/x", "bolaum/*", "acme/**"}, push: []string{"refs/heads/x", "agent/**"}, access: "wrte", api: "wrong",
			wantErr: []string{
				"grant 2 of group agents: repository pattern */x: the owner cannot contain '*'",
				"grant 2 of group agents: repository pattern acme/**",
				"grant 2 of group agents: branch pattern refs/heads/x: write the branch name without refs/heads/",
				"grant 2 of group agents: access must be read or write, not wrte",
				"grant 2 of group agents: api must be read or pr (or empty for none), not wrong",
			},
		},
		{
			name: "only bad patterns", repos: []string{"*/x"}, push: []string{"x"}, access: AccessRead,
			wantErr: []string{
				"grant 2 of group agents: repository pattern */x",
				"grant 2 of group agents: push branches need access write",
			},
		},
		{name: "no patterns", access: AccessRead, wantErr: []string{"grant 2 of group agents: needs at least one repository pattern"}},
		{
			name: "too many patterns", repos: slices.Repeat([]string{"a/b"}, MaxGrantPatterns+1), push: slices.Repeat([]string{"x"}, MaxGrantPatterns+1), access: AccessWrite,
			wantErr: []string{
				"grant 2 of group agents: has 101 repository patterns; a grant has at most 100",
				"grant 2 of group agents: has 101 push patterns; a grant has at most 100",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g, err := ParseGrant(2, holder, tt.repos, tt.access, tt.push, tt.api)
			if len(tt.wantErr) > 0 {
				checkErrorLines(t, err, tt.wantErr)
				return
			}
			if err != nil || len(g.Repos) != tt.repoN || len(g.Push) != tt.pushN || g.ID != 2 || g.Holder != holder || g.Access != tt.access || g.API != tt.api {
				t.Errorf("ParseGrant() = %+v, %v", g, err)
			}
		})
	}
}

// TestUserAndGroupNamespaces gives a user and a group the same name: their grants stay apart.
func TestUserAndGroupNamespaces(t *testing.T) {
	p, err := NewPolicy(State{
		Users:  []User{{Name: "agents"}, {Name: "u"}},
		Groups: []Group{{Name: "agents", Members: []string{"u"}}},
		Grants: []Grant{
			grant(t, 1, "user agents", []string{"o/private"}, AccessRead, nil, PresetNone),
			grant(t, 2, "group agents", []string{"o/shared"}, AccessRead, nil, PresetNone),
		},
		Owners: []string{"o"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	runDecideTests(t, p, []decideTest{
		{name: "user grant", user: "agents", repo: "o/private", op: Fetch{}, want: allowedBy(1, "user agents")},
		{name: "group grant", user: "u", repo: "o/shared", op: Fetch{}, want: allowedBy(2, "group agents")},
		{name: "member does not get the user's grant", user: "u", repo: "o/private", op: Fetch{},
			want: result{Reason: "u cannot access o/private. Repositories allowed: o/shared"}},
		{name: "user does not get the group's grant", user: "agents", repo: "o/shared", op: Fetch{},
			want: result{Reason: "agents cannot access o/shared. Repositories allowed: o/private"}},
	})
}
