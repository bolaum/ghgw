package store

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/bolaum/ghgw/internal/core"
)

func repoGlobs(t *testing.T, ps ...string) []core.RepoGlob {
	t.Helper()
	gs := make([]core.RepoGlob, len(ps))
	for i, p := range ps {
		var err error
		if gs[i], err = core.ParseRepoGlob(p); err != nil {
			t.Fatal(err)
		}
	}
	return gs
}

func branchGlobs(t *testing.T, ps ...string) []core.BranchGlob {
	t.Helper()
	gs := make([]core.BranchGlob, len(ps))
	for i, p := range ps {
		var err error
		if gs[i], err = core.ParseBranchGlob(p); err != nil {
			t.Fatal(err)
		}
	}
	return gs
}

// TestSpecPolicy stores the example policy of SPEC.md section 6 and decides with what it loads.
func TestSpecPolicy(t *testing.T) {
	ctx := context.Background()
	s, _, _ := openStore(t)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, u := range []string{"rpi01-agent", "devct01-agent"} {
		_, err := s.CreateUser(ctx, u)
		must(err)
	}
	must(s.CreateGroup(ctx, "agents"))
	must(s.AddMember(ctx, "agents", "rpi01-agent"))
	must(s.AddMember(ctx, "agents", "devct01-agent"))
	must(s.AddMember(ctx, "agents", "devct01-agent")) // adding twice is not an error
	groupGrant := core.Grant{
		Holder: core.Holder{Kind: core.HolderGroup, Name: "agents"},
		Repos:  repoGlobs(t, "bolaum/*"),
		Access: core.AccessWrite,
		Push:   branchGlobs(t, "agent/**"),
		API:    core.PresetPR,
	}
	userGrant := core.Grant{
		Holder: core.Holder{Kind: core.HolderUser, Name: "devct01-agent"},
		Repos:  repoGlobs(t, "acme/ml-lab"),
		Access: core.AccessWrite,
		Push:   branchGlobs(t, "agent/**"),
		API:    core.PresetPR,
	}
	readGrant := core.Grant{
		Holder: core.Holder{Kind: core.HolderUser, Name: "rpi01-agent"},
		Repos:  repoGlobs(t, "acme/docs", "acme/web-*"),
		Access: core.AccessRead,
	}
	for i, g := range []core.Grant{groupGrant, userGrant, readGrant} {
		id, err := s.AddGrant(ctx, g)
		must(err)
		if id != i+1 {
			t.Errorf("AddGrant() = %d, want %d", id, i+1)
		}
	}
	must(s.AddOwner(ctx, "bolaum", NewSecret("github_pat_bolaum"), timeZero))
	must(s.AddOwner(ctx, "acme", NewSecret("github_pat_acme"), timeZero))

	st, err := s.State(ctx)
	must(err)
	if got := len(st.Users) + len(st.Groups) + len(st.Grants) + len(st.Owners); got != 2+1+3+2 {
		t.Errorf("State() holds %d entries, want 8", got)
	}
	if g := st.Groups[0]; g.Name != "agents" || !slices.Equal(g.Members, []string{"devct01-agent", "rpi01-agent"}) {
		t.Errorf("group = %+v, want agents with both agents", g)
	}
	if !slices.Equal(st.Owners, []string{"acme", "bolaum"}) {
		t.Errorf("owners = %v", st.Owners)
	}
	p, err := core.NewPolicy(st, nil)
	must(err)

	repo := func(s string) core.Repo {
		r, err := core.ParseRepo(s)
		must(err)
		return r
	}
	push := core.Push{DefaultBranch: "main", Updates: []core.RefUpdate{{Ref: "refs/heads/agent/x", Kind: core.UpdateRef}}}
	tests := []struct {
		user, repo string
		op         core.Operation
		want       string
	}{
		{user: "rpi01-agent", repo: "bolaum/ghgw", op: push, want: "allowed by grant 1 of group agents"},
		{user: "devct01-agent", repo: "acme/ml-lab", op: push, want: "allowed by grant 2 of user devct01-agent"},
		{user: "rpi01-agent", repo: "acme/web-app", op: core.Fetch{}, want: "allowed by grant 3 of user rpi01-agent"},
		{user: "rpi01-agent", repo: "acme/web-app", op: core.PushAccess{}, want: "denied"},
		{user: "rpi01-agent", repo: "acme/ml-lab", op: core.Fetch{}, want: "rpi01-agent cannot access acme/ml-lab"},
	}
	for _, tt := range tests {
		d := p.Decide(core.Request{User: tt.user, Repo: repo(tt.repo), Op: tt.op})
		if !strings.Contains(d.String(), tt.want) {
			t.Errorf("Decide(%s, %s, %T) = %s, want %q", tt.user, tt.repo, tt.op, d, tt.want)
		}
	}
}

func TestUsers(t *testing.T) {
	ctx := context.Background()
	s, _, _ := openStore(t)
	key, err := s.CreateUser(ctx, "agent")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := hashKey(userKeyPrefix, key); !ok {
		t.Error("CreateUser() returned a malformed key")
	}
	if u, err := s.AuthenticateUser(ctx, key); err != nil || u != (core.User{Name: "agent"}) {
		t.Errorf("AuthenticateUser() = %+v, %v; want agent", u, err)
	}

	if err := s.SetUserDisabled(ctx, "agent", true); err != nil {
		t.Fatal(err)
	}
	// A disabled user still authenticates: the policy denies it with a reason.
	if u, err := s.AuthenticateUser(ctx, key); err != nil || !u.Disabled {
		t.Errorf("AuthenticateUser(disabled) = %+v, %v; want the disabled user", u, err)
	}
	if err := s.SetUserDisabled(ctx, "agent", false); err != nil {
		t.Fatal(err)
	}

	newKey, err := s.RotateUserKey(ctx, "agent")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AuthenticateUser(ctx, key); !errors.Is(err, ErrUnknownKey) {
		t.Errorf("AuthenticateUser(old key) error = %v, want ErrUnknownKey", err)
	}
	if u, err := s.AuthenticateUser(ctx, newKey); err != nil || u.Name != "agent" {
		t.Errorf("AuthenticateUser(new key) = %+v, %v; want agent", u, err)
	}

	if err := s.DeleteUser(ctx, "agent"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AuthenticateUser(ctx, newKey); !errors.Is(err, ErrUnknownKey) {
		t.Errorf("AuthenticateUser(deleted user) error = %v, want ErrUnknownKey", err)
	}
}

func TestAuthenticateUserRejects(t *testing.T) {
	s, _, admin := openStore(t)
	key, err := s.CreateUser(context.Background(), "agent")
	if err != nil {
		t.Fatal(err)
	}
	other, _ := newKey(userKeyPrefix)
	for name, k := range map[string]Secret{
		"unknown well-formed key": other,
		"empty":                   {},
		"admin token":             admin,
		"key with a newline":      NewSecret(key.Reveal() + "\n"),
		"key without prefix":      NewSecret(strings.TrimPrefix(key.Reveal(), userKeyPrefix)),
		"huge":                    NewSecret(strings.Repeat("ghgw_", 1<<18)),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := s.AuthenticateUser(context.Background(), k)
			wantErr(t, err, ErrUnknownKey, "unknown ghgw key")
		})
	}
}

func TestChangeErrors(t *testing.T) {
	ctx := context.Background()
	s, _, _ := openStore(t)
	if _, err := s.CreateUser(ctx, "agent"); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateGroup(ctx, "agents"); err != nil {
		t.Fatal(err)
	}
	grant := func(holder core.Holder, mod func(*core.Grant)) core.Grant {
		g := core.Grant{Holder: holder, Repos: repoGlobs(t, "acme/app"), Access: core.AccessWrite, Push: branchGlobs(t, "agent/*")}
		if mod != nil {
			mod(&g)
		}
		return g
	}
	user := core.Holder{Kind: core.HolderUser, Name: "agent"}
	addGrant := func(g core.Grant) error {
		_, err := s.AddGrant(ctx, g)
		return err
	}
	tests := []struct {
		name   string
		change func() error
		kind   error
		want   string
	}{
		{name: "duplicate user", change: func() error { _, err := s.CreateUser(ctx, "agent"); return err }, kind: ErrExists, want: "user agent already exists"},
		{name: "upper-case user", change: func() error { _, err := s.CreateUser(ctx, "Agent"); return err }, kind: ErrInvalid, want: "user name Agent must be"},
		{name: "long user name", change: func() error { _, err := s.CreateUser(ctx, strings.Repeat("a", 65)); return err }, kind: ErrInvalid, want: "must be 1 to 64"},
		{name: "empty user name", change: func() error { _, err := s.CreateUser(ctx, ""); return err }, kind: ErrInvalid, want: "must be 1 to 64"},
		{name: "rotate unknown user", change: func() error { _, err := s.RotateUserKey(ctx, "nobody"); return err }, kind: ErrNotFound, want: "user nobody does not exist"},
		{name: "disable unknown user", change: func() error { return s.SetUserDisabled(ctx, "nobody", true) }, kind: ErrNotFound, want: "user nobody does not exist"},
		{name: "delete unknown user", change: func() error { return s.DeleteUser(ctx, "nobody") }, kind: ErrNotFound, want: "user nobody does not exist"},
		{name: "duplicate group", change: func() error { return s.CreateGroup(ctx, "agents") }, kind: ErrExists, want: "group agents already exists"},
		{name: "invalid group name", change: func() error { return s.CreateGroup(ctx, "a b") }, kind: ErrInvalid, want: "group name a b must be"},
		{name: "delete unknown group", change: func() error { return s.DeleteGroup(ctx, "nobody") }, kind: ErrNotFound, want: "group nobody does not exist"},
		{name: "member of unknown group", change: func() error { return s.AddMember(ctx, "nobody", "agent") }, kind: ErrNotFound, want: "group nobody does not exist"},
		{name: "unknown member", change: func() error { return s.AddMember(ctx, "agents", "nobody") }, kind: ErrNotFound, want: "user nobody does not exist"},
		{name: "remove non-member", change: func() error { return s.RemoveMember(ctx, "agents", "agent") }, kind: ErrNotFound, want: "user agent is not a member of group agents"},
		{name: "grant with an ID", change: func() error { return addGrant(grant(user, func(g *core.Grant) { g.ID = 7 })) }, kind: ErrInvalid, want: "the store assigns one"},
		{name: "grant without holder", change: func() error { return addGrant(grant(core.Holder{}, nil)) }, kind: ErrInvalid, want: "belongs to a user or a group"},
		{name: "grant of unknown user", change: func() error { return addGrant(grant(core.Holder{Kind: core.HolderUser, Name: "nobody"}, nil)) }, kind: ErrNotFound, want: "user nobody does not exist; create it first"},
		{name: "grant of unknown group", change: func() error { return addGrant(grant(core.Holder{Kind: core.HolderGroup, Name: "nobody"}, nil)) }, kind: ErrNotFound, want: "group nobody does not exist"},
		{name: "grant without repositories", change: func() error { return addGrant(grant(user, func(g *core.Grant) { g.Repos = nil })) }, kind: ErrInvalid, want: "needs at least one repository pattern"},
		{name: "grant with a zero pattern", change: func() error { return addGrant(grant(user, func(g *core.Grant) { g.Push = []core.BranchGlob{{}} })) }, kind: ErrInvalid, want: "push pattern 1 is empty"},
		{name: "push with read access", change: func() error { return addGrant(grant(user, func(g *core.Grant) { g.Access = core.AccessRead })) }, kind: ErrInvalid, want: "push branches need access write"},
		{name: "unknown access", change: func() error { return addGrant(grant(user, func(g *core.Grant) { g.Access = "admin" })) }, kind: ErrInvalid, want: "access must be read or write, not admin"},
		{name: "unknown preset", change: func() error { return addGrant(grant(user, func(g *core.Grant) { g.API = "all" })) }, kind: ErrInvalid, want: `api must be read or pr`},
		{
			name: "too many repository patterns",
			change: func() error {
				return addGrant(grant(user, func(g *core.Grant) { g.Repos = slices.Repeat(g.Repos, MaxGrantPatterns+1) }))
			},
			kind: ErrInvalid, want: "at most 100 repository patterns, not 101",
		},
		{
			name: "too many push patterns",
			change: func() error {
				return addGrant(grant(user, func(g *core.Grant) { g.Push = slices.Repeat(g.Push, MaxGrantPatterns+1) }))
			},
			kind: ErrInvalid, want: "at most 100 push patterns",
		},
		{name: "delete unknown grant", change: func() error { return s.DeleteGrant(ctx, 99) }, kind: ErrNotFound, want: "grant 99 does not exist"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantErr(t, tt.change(), tt.kind, tt.want)
		})
	}
	st, err := s.State(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Users) != 1 || len(st.Groups) != 1 || len(st.Grants) != 0 || len(st.Groups[0].Members) != 0 {
		t.Errorf("failed changes left state behind: %+v", st)
	}
}

func TestDeletesCascade(t *testing.T) {
	ctx := context.Background()
	s, _, _ := openStore(t)
	for _, u := range []string{"a", "b"} {
		if _, err := s.CreateUser(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.CreateGroup(ctx, "g"); err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{"a", "b"} {
		if err := s.AddMember(ctx, "g", u); err != nil {
			t.Fatal(err)
		}
	}
	add := func(h core.Holder) int {
		id, err := s.AddGrant(ctx, core.Grant{Holder: h, Repos: repoGlobs(t, "acme/*"), Access: core.AccessRead})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	add(core.Holder{Kind: core.HolderUser, Name: "a"})
	add(core.Holder{Kind: core.HolderGroup, Name: "g"})
	bGrant := add(core.Holder{Kind: core.HolderUser, Name: "b"})

	if err := s.DeleteUser(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteGroup(ctx, "g"); err != nil {
		t.Fatal(err)
	}
	st, err := s.State(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Users) != 1 || len(st.Groups) != 0 || len(st.Grants) != 1 || st.Grants[0].ID != bGrant {
		t.Errorf("after deleting user a and group g, state = %+v; want user b and its grant", st)
	}

	// Grant IDs are never reused, so an old ID in an audit record never names a new grant.
	if err := s.DeleteGrant(ctx, bGrant); err != nil {
		t.Fatal(err)
	}
	if id := add(core.Holder{Kind: core.HolderUser, Name: "b"}); id != bGrant+1 {
		t.Errorf("AddGrant() after deleting grant %d = %d, want %d", bGrant, id, bGrant+1)
	}
}

func TestHostileNamesInErrors(t *testing.T) {
	ctx := context.Background()
	s, _, _ := openStore(t)
	if _, err := s.CreateUser(ctx, "agent"); err != nil {
		t.Fatal(err)
	}
	huge := strings.Repeat("x", 1<<20)
	tests := []struct {
		name string
		call func(name string) error
	}{
		{name: "create user", call: func(n string) error { _, err := s.CreateUser(ctx, n); return err }},
		{name: "rotate user key", call: func(n string) error { _, err := s.RotateUserKey(ctx, n); return err }},
		{name: "delete user", call: func(n string) error { return s.DeleteUser(ctx, n) }},
		{name: "create group", call: func(n string) error { return s.CreateGroup(ctx, n) }},
		{name: "add member", call: func(n string) error { return s.AddMember(ctx, n, n) }},
		{name: "remove member", call: func(n string) error { return s.RemoveMember(ctx, n, n) }},
		{
			name: "grant",
			call: func(n string) error {
				_, err := s.AddGrant(ctx, core.Grant{Holder: core.Holder{Kind: core.HolderGroup, Name: n}, Repos: repoGlobs(t, "a/b"), Access: core.AccessRead})
				return err
			},
		},
		{name: "add owner", call: func(n string) error { return s.AddOwner(ctx, n, NewSecret("t"), timeZero) }},
		{name: "rotate owner", call: func(n string) error { return s.RotateOwner(ctx, n, NewSecret("t"), timeZero) }},
		{name: "credential", call: func(n string) error { _, err := s.Credential(ctx, n); return err }},
		{
			name: "grant access",
			call: func(n string) error {
				_, err := s.AddGrant(ctx, core.Grant{Holder: core.Holder{Kind: core.HolderUser, Name: "agent"}, Repos: repoGlobs(t, "a/b"), Access: core.Access(n)})
				return err
			},
		},
	}
	for _, tt := range tests {
		for _, n := range []string{"x\ny\x1b[2J", "x\u202ey", huge} {
			err := tt.call(n)
			if err == nil {
				t.Errorf("%s: no error", tt.name)
				continue
			}
			msg := err.Error()
			// core renders an identifier within 1 KiB; the store cuts names at 100 bytes.
			if strings.ContainsAny(msg, "\n\x1b\u202e") || len(msg) > 1024+200 {
				t.Errorf("%s: the error renders the name unsafely: %.200q", tt.name, msg)
			}
		}
	}
}
