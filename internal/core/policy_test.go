package core

import (
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
			wantErr: []string{`user name "Agent"`, `user name ""`, `group name "my group"`, `owner "-acme"`},
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
					},
				}
			},
			wantErr: []string{
				"grant 0: the ID must be positive",
				"grant 1 of user ghost: user ghost does not exist; create it first",
				"grant 2 of group ghosts: group ghosts does not exist; create it first",
				"grant 3 of user rpi01-agent: needs at least one repository pattern",
				"grant 4 of user rpi01-agent: has an empty repository pattern",
				`grant 5 of user rpi01-agent: access must be read or write, not "admin"`,
				`grant 6 of user rpi01-agent: access must be read or write, not ""`,
				"grant 7 of user rpi01-agent: push branches need access write",
				`grant 8 of user rpi01-agent: api must be read or pr (or empty for none), not "admin"`,
				"grant 9 of user rpi01-agent: has an empty push pattern",
				"grant 10 of holder rpi01-agent: the holder must be a user or a group",
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
		})
	}
}

func TestNewPolicyCopiesState(t *testing.T) {
	s := State{
		Users:  []User{{Name: "a"}},
		Grants: []Grant{grant(t, 1, "user a", []string{"bolaum/x"}, AccessRead, nil, PresetRead)},
	}
	p, err := NewPolicy(s, nil)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := ParseRepoGlob("acme/*")
	s.Grants[0].Repos[0] = other
	s.Grants[0].Access = AccessWrite
	g := p.grants["a"][0]
	if g.Repos[0].String() != "bolaum/x" || g.Access != AccessRead {
		t.Errorf("policy grant changed with the state it was built from: %+v", g)
	}
}
