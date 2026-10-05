package core

import (
	"fmt"
	"reflect"
	"testing"
)

// testPolicy is the policy of SPEC.md section 6 plus users and grants for the other rules.
func testPolicy(t *testing.T) *Policy {
	t.Helper()
	bolaum := []string{"bolaum/*"}
	agent := []string{"agent/**"}
	p, err := NewPolicy(State{
		Users: []User{
			{Name: "rpi01-agent"},
			{Name: "devct01-agent"},
			{Name: "reviewer"},
			{Name: "old-agent", Disabled: true},
			{Name: "lonely"},
			{Name: "multi"},
			{Name: "nopush"},
		},
		Groups: []Group{{Name: "agents", Members: []string{"rpi01-agent", "devct01-agent", "old-agent"}}},
		Grants: []Grant{
			grant(t, 1, "group agents", bolaum, AccessWrite, agent, PresetPR),
			grant(t, 2, "user devct01-agent", []string{"acme/ml-lab"}, AccessWrite, agent, PresetPR),
			grant(t, 3, "user reviewer", bolaum, AccessRead, nil, PresetPR),
			grant(t, 4, "user rpi01-agent", []string{"nocred/app"}, AccessWrite, agent, PresetRead),
			grant(t, 5, "user multi", []string{"bolaum/app"}, AccessWrite, []string{"feature/*"}, PresetRead),
			grant(t, 6, "user multi", bolaum, AccessWrite, agent, PresetNone),
			grant(t, 7, "user nopush", bolaum, AccessWrite, nil, PresetRead),
		},
		Owners: []string{"Bolaum", "acme"},
	}, testRESTTable(t))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// testRESTTable has one operation per class. It is not the real operation table.
func testRESTTable(t *testing.T) *RESTTable {
	t.Helper()
	table, err := NewRESTTable([]RESTOperation{
		{Name: "pulls.list", Method: "GET", Path: "/repos/{owner}/{repo}/pulls", Class: ClassRead},
		{Name: "pulls.create", Method: "POST", Path: "/repos/{owner}/{repo}/pulls", Class: ClassPR},
		{Name: "contents.update", Method: "PUT", Path: "/repos/{owner}/{repo}/contents/{path}", Class: ClassCodeChange},
		{Name: "git.create-ref", Method: "POST", Path: "/repos/{owner}/{repo}/git/refs", Class: ClassCodeChange},
		{Name: "pulls.merge", Method: "PUT", Path: "/repos/{owner}/{repo}/pulls/{pull_number}/merge", Class: ClassMerge},
		{Name: "hooks.create", Method: "POST", Path: "/repos/{owner}/{repo}/hooks", Class: ClassAdmin},
		{Name: "users.get", Method: "GET", Path: "/user", Class: ClassUnscoped},
		{Name: "rate_limit.get", Method: "GET", Path: "/rate_limit", Class: ClassGlobal},
		{Name: "meta.get", Method: "GET", Path: "/meta", Class: ClassGlobal},
	})
	if err != nil {
		t.Fatal(err)
	}
	return table
}

// result is a Decision reduced to comparable values, with grants as IDs (0 for none).
type result struct {
	Allowed bool
	Reason  string
	Grant   int
	Refs    []refResult
}

type refResult struct {
	Ref     string
	Allowed bool
	Reason  string
	Grant   int
}

func summarize(d Decision) result {
	id := func(g *Grant) int {
		if g == nil {
			return 0
		}
		return g.ID
	}
	r := result{Allowed: d.Allowed, Reason: d.Reason, Grant: id(d.Grant)}
	for _, rd := range d.Refs {
		r.Refs = append(r.Refs, refResult{Ref: rd.Ref, Allowed: rd.Allowed, Reason: rd.Reason, Grant: id(rd.Grant)})
	}
	return r
}

func create(ref string) RefUpdate { return RefUpdate{Ref: ref, Kind: CreateRef} }
func update(ref string) RefUpdate { return RefUpdate{Ref: ref, Kind: UpdateRef} }
func remove(ref string) RefUpdate { return RefUpdate{Ref: ref, Kind: DeleteRef} }

type decideTest struct {
	name string
	user string
	repo string // empty for no repository
	op   Operation
	want result
}

func runDecideTests(t *testing.T, p *Policy, tests []decideTest) {
	t.Helper()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var repo Repo
			if tt.repo != "" {
				repo = mustRepo(t, tt.repo)
			}
			got := summarize(p.Decide(Request{User: tt.user, Repo: repo, Op: tt.op}))
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Decide() =\n%+v\nwant\n%+v", got, tt.want)
			}
		})
	}
}

func allowedBy(id int, holder string) result {
	return result{Allowed: true, Reason: "allowed by " + grantName(id, holder), Grant: id}
}

func grantName(id int, holder string) string {
	return fmt.Sprintf("grant %d of %s", id, holder)
}

func TestDecidePolicy(t *testing.T) {
	runDecideTests(t, testPolicy(t), []decideTest{
		{
			name: "group grant",
			user: "rpi01-agent", repo: "bolaum/ghgw", op: Fetch{},
			want: allowedBy(1, "group agents"),
		},
		{
			name: "repository names are case-insensitive",
			user: "rpi01-agent", repo: "BOLAUM/GhGw", op: Fetch{},
			want: allowedBy(1, "group agents"),
		},
		{
			name: "own grant next to group grants",
			user: "devct01-agent", repo: "acme/ml-lab", op: Fetch{},
			want: allowedBy(2, "user devct01-agent"),
		},
		{
			name: "group grant next to own grants",
			user: "devct01-agent", repo: "bolaum/x", op: Fetch{},
			want: allowedBy(1, "group agents"),
		},
		{
			name: "several grants match: the lowest ID is cited",
			user: "multi", repo: "bolaum/app", op: Fetch{},
			want: allowedBy(5, "user multi"),
		},
		{
			name: "repository not granted",
			user: "devct01-agent", repo: "acme/secret", op: Fetch{},
			want: result{Reason: "devct01-agent cannot access acme/secret. Repositories allowed: bolaum/*, acme/ml-lab"},
		},
		{
			name: "deny by default",
			user: "lonely", repo: "bolaum/ghgw", op: Fetch{},
			want: result{Reason: "lonely cannot access bolaum/ghgw. Repositories allowed: none"},
		},
		{
			name: "unknown user",
			user: "ghost", repo: "bolaum/ghgw", op: Fetch{},
			want: result{Reason: "unknown user ghost; ask the admin to create it"},
		},
		{
			name: "disabled user",
			user: "old-agent", repo: "bolaum/ghgw", op: Fetch{},
			want: result{Reason: "user old-agent is disabled; ask the admin to enable it"},
		},
		{
			name: "owner without credential",
			user: "rpi01-agent", repo: "nocred/app", op: Fetch{},
			want: result{Reason: "ghgw has no credential for owner nocred; ask the admin to add one"},
		},
		{
			name: "owner credential matched case-insensitively",
			user: "rpi01-agent", repo: "bolaum/ghgw", op: Fetch{},
			want: allowedBy(1, "group agents"),
		},
		{
			name: "no repository",
			user: "rpi01-agent", op: Fetch{},
			want: result{Reason: "fetch needs a repository"},
		},
		{
			name: "no operation",
			user: "rpi01-agent", repo: "bolaum/ghgw",
			want: result{Reason: "unknown operation"},
		},
	})
}

func TestDecideFetch(t *testing.T) {
	runDecideTests(t, testPolicy(t), []decideTest{
		{
			name: "write access includes read",
			user: "rpi01-agent", repo: "bolaum/ghgw", op: Fetch{},
			want: allowedBy(1, "group agents"),
		},
		{
			name: "read access",
			user: "reviewer", repo: "bolaum/ghgw", op: Fetch{},
			want: allowedBy(3, "user reviewer"),
		},
	})
}

func TestDecidePush(t *testing.T) {
	const (
		agentX  = "refs/heads/agent/x"
		main    = "refs/heads/main"
		feature = "refs/heads/feature/x"
		tag     = "refs/tags/v1"
	)
	allowedRef := func(ref string, id int, holder string) refResult {
		return refResult{Ref: ref, Allowed: true, Reason: "allowed by " + grantName(id, holder), Grant: id}
	}
	deniedRef := func(ref, reason string) refResult { return refResult{Ref: ref, Reason: reason} }
	allowedPush := func(id int, holder string, refs ...refResult) result {
		r := allowedBy(id, holder)
		r.Refs = refs
		return r
	}
	deniedPush := func(reason string, refs ...refResult) result {
		return result{Reason: reason, Refs: refs}
	}
	const (
		defaultBranch = "push to the default branch is not allowed; allowed branches: agent/**"
		another       = "another ref was rejected"
	)

	runDecideTests(t, testPolicy(t), []decideTest{
		{
			name: "create an allowed branch",
			user: "rpi01-agent", repo: "bolaum/ghgw", op: Push{DefaultBranch: "main", Updates: []RefUpdate{create(agentX)}},
			want: allowedPush(1, "group agents", allowedRef(agentX, 1, "group agents")),
		},
		{
			name: "update (or force-push) an allowed branch",
			user: "rpi01-agent", repo: "bolaum/ghgw", op: Push{DefaultBranch: "main", Updates: []RefUpdate{update(agentX)}},
			want: allowedPush(1, "group agents", allowedRef(agentX, 1, "group agents")),
		},
		{
			name: "delete an allowed branch",
			user: "rpi01-agent", repo: "bolaum/ghgw", op: Push{DefaultBranch: "main", Updates: []RefUpdate{remove(agentX)}},
			want: allowedPush(1, "group agents", allowedRef(agentX, 1, "group agents")),
		},
		{
			name: "nested branch under **",
			user: "rpi01-agent", repo: "bolaum/ghgw", op: Push{DefaultBranch: "main", Updates: []RefUpdate{create("refs/heads/agent/a/b")}},
			want: allowedPush(1, "group agents", allowedRef("refs/heads/agent/a/b", 1, "group agents")),
		},
		{
			name: "branch outside the globs",
			user: "rpi01-agent", repo: "bolaum/ghgw", op: Push{DefaultBranch: "main", Updates: []RefUpdate{create(feature)}},
			want: deniedPush("push to branch feature/x is not allowed; allowed branches: agent/**",
				deniedRef(feature, "push to branch feature/x is not allowed; allowed branches: agent/**")),
		},
		{
			name: "delete a branch outside the globs",
			user: "rpi01-agent", repo: "bolaum/ghgw", op: Push{DefaultBranch: "main", Updates: []RefUpdate{remove(feature)}},
			want: deniedPush("deleting branch feature/x is not allowed; allowed branches: agent/**",
				deniedRef(feature, "deleting branch feature/x is not allowed; allowed branches: agent/**")),
		},
		{
			name: "default branch",
			user: "rpi01-agent", repo: "bolaum/ghgw", op: Push{DefaultBranch: "main", Updates: []RefUpdate{update(main)}},
			want: deniedPush(defaultBranch, deniedRef(main, defaultBranch)),
		},
		{
			name: "create the default branch",
			user: "rpi01-agent", repo: "bolaum/ghgw", op: Push{DefaultBranch: "main", Updates: []RefUpdate{create(main)}},
			want: deniedPush(defaultBranch, deniedRef(main, defaultBranch)),
		},
		{
			name: "default branch in another case",
			user: "rpi01-agent", repo: "bolaum/ghgw", op: Push{DefaultBranch: "main", Updates: []RefUpdate{update("refs/heads/MAIN")}},
			want: deniedPush(defaultBranch, deniedRef("refs/heads/MAIN", defaultBranch)),
		},
		{
			name: "delete the default branch",
			user: "rpi01-agent", repo: "bolaum/ghgw", op: Push{DefaultBranch: "main", Updates: []RefUpdate{remove(main)}},
			want: deniedPush("deleting the default branch is not allowed; allowed branches: agent/**",
				deniedRef(main, "deleting the default branch is not allowed; allowed branches: agent/**")),
		},
		{
			name: "default branch matched by a push glob",
			user: "rpi01-agent", repo: "bolaum/ghgw", op: Push{DefaultBranch: "agent/x", Updates: []RefUpdate{update(agentX)}},
			want: deniedPush(defaultBranch, deniedRef(agentX, defaultBranch)),
		},
		{
			name: "create a tag",
			user: "rpi01-agent", repo: "bolaum/ghgw", op: Push{DefaultBranch: "main", Updates: []RefUpdate{create(tag)}},
			want: deniedPush("pushing tags is not allowed; allowed branches: agent/**",
				deniedRef(tag, "pushing tags is not allowed; allowed branches: agent/**")),
		},
		{
			name: "delete a tag",
			user: "rpi01-agent", repo: "bolaum/ghgw", op: Push{DefaultBranch: "main", Updates: []RefUpdate{remove(tag)}},
			want: deniedPush("pushing tags is not allowed; allowed branches: agent/**",
				deniedRef(tag, "pushing tags is not allowed; allowed branches: agent/**")),
		},
		{
			name: "other refs",
			user: "rpi01-agent", repo: "bolaum/ghgw", op: Push{DefaultBranch: "main", Updates: []RefUpdate{update("refs/notes/commits")}},
			want: deniedPush("pushing refs/notes/commits is not allowed, only branches can be pushed; allowed branches: agent/**",
				deniedRef("refs/notes/commits", "pushing refs/notes/commits is not allowed, only branches can be pushed; allowed branches: agent/**")),
		},
		{
			name: "invalid ref name",
			user: "rpi01-agent", repo: "bolaum/ghgw", op: Push{DefaultBranch: "main", Updates: []RefUpdate{update("refs/heads/agent/../main")}},
			want: deniedPush(`invalid ref name "refs/heads/agent/../main": cannot contain ".."; allowed branches: agent/**`,
				deniedRef("refs/heads/agent/../main", `invalid ref name "refs/heads/agent/../main": cannot contain ".."; allowed branches: agent/**`)),
		},
		{
			name: "unknown update kind",
			user: "rpi01-agent", repo: "bolaum/ghgw", op: Push{DefaultBranch: "main", Updates: []RefUpdate{{Ref: agentX}}},
			want: deniedPush("unknown update of refs/heads/agent/x; allowed branches: agent/**",
				deniedRef(agentX, "unknown update of refs/heads/agent/x; allowed branches: agent/**")),
		},
		{
			name: "all or nothing",
			user: "rpi01-agent", repo: "bolaum/ghgw",
			op:   Push{DefaultBranch: "main", Updates: []RefUpdate{create(agentX), update(main)}},
			want: deniedPush(defaultBranch, deniedRef(agentX, another), deniedRef(main, defaultBranch)),
		},
		{
			name: "several rejected refs keep their own reasons; the first one is the push's reason",
			user: "rpi01-agent", repo: "bolaum/ghgw",
			op: Push{DefaultBranch: "main", Updates: []RefUpdate{create(feature), create(tag), update(agentX)}},
			want: deniedPush("push to branch feature/x is not allowed; allowed branches: agent/**",
				deniedRef(feature, "push to branch feature/x is not allowed; allowed branches: agent/**"),
				deniedRef(tag, "pushing tags is not allowed; allowed branches: agent/**"),
				deniedRef(agentX, another)),
		},
		{
			name: "read-only access",
			user: "reviewer", repo: "bolaum/ghgw", op: Push{DefaultBranch: "main", Updates: []RefUpdate{create(agentX), create(feature)}},
			want: deniedPush("reviewer has read-only access to bolaum/ghgw; pushing needs a grant with access write",
				deniedRef(agentX, "reviewer has read-only access to bolaum/ghgw; pushing needs a grant with access write"),
				deniedRef(feature, "reviewer has read-only access to bolaum/ghgw; pushing needs a grant with access write")),
		},
		{
			name: "repository not granted",
			user: "rpi01-agent", repo: "acme/secret", op: Push{DefaultBranch: "main", Updates: []RefUpdate{create(agentX)}},
			want: deniedPush("rpi01-agent cannot access acme/secret. Repositories allowed: bolaum/*, nocred/app",
				deniedRef(agentX, "rpi01-agent cannot access acme/secret. Repositories allowed: bolaum/*, nocred/app")),
		},
		{
			name: "disabled user",
			user: "old-agent", repo: "bolaum/ghgw", op: Push{DefaultBranch: "main", Updates: []RefUpdate{create(agentX)}},
			want: deniedPush("user old-agent is disabled; ask the admin to enable it",
				deniedRef(agentX, "user old-agent is disabled; ask the admin to enable it")),
		},
		{
			name: "owner without credential",
			user: "rpi01-agent", repo: "nocred/app", op: Push{DefaultBranch: "main", Updates: []RefUpdate{create(agentX)}},
			want: deniedPush("ghgw has no credential for owner nocred; ask the admin to add one",
				deniedRef(agentX, "ghgw has no credential for owner nocred; ask the admin to add one")),
		},
		{
			name: "write access with no push branches",
			user: "nopush", repo: "bolaum/ghgw", op: Push{DefaultBranch: "main", Updates: []RefUpdate{create(agentX)}},
			want: deniedPush("push to branch agent/x is not allowed; allowed branches: none",
				deniedRef(agentX, "push to branch agent/x is not allowed; allowed branches: none")),
		},
		{
			name: "refs allowed by different grants",
			user: "multi", repo: "bolaum/app", op: Push{DefaultBranch: "main", Updates: []RefUpdate{create(feature), create(agentX)}},
			want: result{
				Allowed: true,
				Reason:  "allowed by grant 5 of user multi, grant 6 of user multi",
				Refs:    []refResult{allowedRef(feature, 5, "user multi"), allowedRef(agentX, 6, "user multi")},
			},
		},
		{
			name: "allowed branches are the union of the matching write grants",
			user: "multi", repo: "bolaum/app", op: Push{DefaultBranch: "main", Updates: []RefUpdate{update(main)}},
			want: deniedPush("push to the default branch is not allowed; allowed branches: feature/*, agent/**",
				deniedRef(main, "push to the default branch is not allowed; allowed branches: feature/*, agent/**")),
		},
		{
			name: "push globs of grants for other repositories do not apply",
			user: "multi", repo: "bolaum/other", op: Push{DefaultBranch: "main", Updates: []RefUpdate{create(feature)}},
			want: deniedPush("push to branch feature/x is not allowed; allowed branches: agent/**",
				deniedRef(feature, "push to branch feature/x is not allowed; allowed branches: agent/**")),
		},
		{
			name: "no updates: write access check",
			user: "rpi01-agent", repo: "bolaum/ghgw", op: Push{},
			want: allowedBy(1, "group agents"),
		},
		{
			name: "no updates: read-only access",
			user: "reviewer", repo: "bolaum/ghgw", op: Push{},
			want: result{Reason: "reviewer has read-only access to bolaum/ghgw; pushing needs a grant with access write"},
		},
		{
			name: "unknown default branch",
			user: "rpi01-agent", repo: "bolaum/ghgw", op: Push{Updates: []RefUpdate{create(agentX)}},
			want: deniedPush("the default branch of bolaum/ghgw is unknown, so the push cannot be checked; try again",
				deniedRef(agentX, "the default branch of bolaum/ghgw is unknown, so the push cannot be checked; try again")),
		},
		{
			name: "no repository",
			user: "rpi01-agent", op: Push{DefaultBranch: "main", Updates: []RefUpdate{create(agentX)}},
			want: deniedPush("push needs a repository", deniedRef(agentX, "push needs a repository")),
		},
	})
}

func TestDecideREST(t *testing.T) {
	const (
		codeChange = "code changes go through git push only; push to an allowed branch instead"
		everyUser  = "allowed for every user"
	)
	runDecideTests(t, testPolicy(t), []decideTest{
		{
			name: "read preset allows read operations",
			user: "multi", repo: "bolaum/app", op: REST{Name: "pulls.list"},
			want: allowedBy(5, "user multi"),
		},
		{
			name: "pr preset allows read operations",
			user: "rpi01-agent", repo: "bolaum/ghgw", op: REST{Name: "pulls.list"},
			want: allowedBy(1, "group agents"),
		},
		{
			name: "pr preset allows pr operations",
			user: "rpi01-agent", repo: "bolaum/ghgw", op: REST{Name: "pulls.create"},
			want: allowedBy(1, "group agents"),
		},
		{
			name: "api preset does not depend on git access",
			user: "reviewer", repo: "bolaum/ghgw", op: REST{Name: "pulls.create"},
			want: allowedBy(3, "user reviewer"),
		},
		{
			name: "read preset denies pr operations",
			user: "rpi01-agent", repo: "nocred/app", op: REST{Name: "pulls.create"},
			want: result{Reason: "pulls.create on nocred/app needs API preset pr; rpi01-agent has: read (grant 4 of user rpi01-agent)"},
		},
		{
			name: "no preset denies read operations",
			user: "multi", repo: "bolaum/other", op: REST{Name: "pulls.list"},
			want: result{Reason: "pulls.list on bolaum/other needs API preset read; multi has: none (grant 6 of user multi)"},
		},
		{
			name: "every matching grant is listed",
			user: "multi", repo: "bolaum/app", op: REST{Name: "pulls.create"},
			want: result{Reason: "pulls.create on bolaum/app needs API preset pr; multi has: read (grant 5 of user multi), none (grant 6 of user multi)"},
		},
		{
			name: "contents writes are a hard rule",
			user: "rpi01-agent", repo: "bolaum/ghgw", op: REST{Name: "contents.update"},
			want: result{Reason: "contents.update is not allowed: " + codeChange},
		},
		{
			name: "git data writes are a hard rule",
			user: "rpi01-agent", repo: "bolaum/ghgw", op: REST{Name: "git.create-ref"},
			want: result{Reason: "git.create-ref is not allowed: " + codeChange},
		},
		{
			name: "merging is a hard rule",
			user: "rpi01-agent", repo: "bolaum/ghgw", op: REST{Name: "pulls.merge"},
			want: result{Reason: "pulls.merge is not allowed: ghgw never merges pull requests; ask a person to merge"},
		},
		{
			name: "repository administration is a hard rule",
			user: "rpi01-agent", repo: "bolaum/ghgw", op: REST{Name: "hooks.create"},
			want: result{Reason: "hooks.create is not allowed: repository administration is not available through ghgw"},
		},
		{
			name: "repository access is checked before the hard rules",
			user: "rpi01-agent", repo: "acme/secret", op: REST{Name: "pulls.merge"},
			want: result{Reason: "rpi01-agent cannot access acme/secret. Repositories allowed: bolaum/*, nocred/app"},
		},
		{
			name: "endpoints that are not repository-scoped are a hard rule",
			user: "rpi01-agent", op: REST{Name: "users.get"},
			want: result{Reason: "users.get is not allowed: only repository endpoints (repos/{owner}/{repo}/...), rate_limit and meta are available"},
		},
		{
			name: "rate_limit is allowed for every user",
			user: "rpi01-agent", op: REST{Name: "rate_limit.get"},
			want: result{Allowed: true, Reason: everyUser},
		},
		{
			name: "meta is allowed without any grant",
			user: "lonely", op: REST{Name: "meta.get"},
			want: result{Allowed: true, Reason: everyUser},
		},
		{
			name: "global operations still need an enabled user",
			user: "old-agent", op: REST{Name: "meta.get"},
			want: result{Reason: "user old-agent is disabled; ask the admin to enable it"},
		},
		{
			name: "global operation with a repository",
			user: "rpi01-agent", repo: "bolaum/ghgw", op: REST{Name: "rate_limit.get"},
			want: result{Reason: "rate_limit.get is not repository-scoped; call it without a repository"},
		},
		{
			name: "repository operation without a repository",
			user: "rpi01-agent", op: REST{Name: "pulls.list"},
			want: result{Reason: "pulls.list needs a repository"},
		},
		{
			name: "unknown operation",
			user: "rpi01-agent", repo: "bolaum/ghgw", op: REST{Name: "pulls.fly"},
			want: result{Reason: `unknown operation "pulls.fly"; ghgw only forwards the API operations it knows`},
		},
		{
			name: "owner without credential",
			user: "rpi01-agent", repo: "nocred/app", op: REST{Name: "pulls.list"},
			want: result{Reason: "ghgw has no credential for owner nocred; ask the admin to add one"},
		},
	})

	t.Run("no table", func(t *testing.T) {
		p, err := NewPolicy(State{
			Users:  []User{{Name: "a"}},
			Grants: []Grant{grant(t, 1, "user a", []string{"bolaum/*"}, AccessRead, nil, PresetPR)},
			Owners: []string{"bolaum"},
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		runDecideTests(t, p, []decideTest{{
			name: "every operation is unknown",
			user: "a", repo: "bolaum/ghgw", op: REST{Name: "pulls.list"},
			want: result{Reason: `unknown operation "pulls.list"; ghgw only forwards the API operations it knows`},
		}})
	})
}

func TestDecisionGrantIsACopy(t *testing.T) {
	p := testPolicy(t)
	req := Request{User: "rpi01-agent", Repo: mustRepo(t, "bolaum/ghgw"), Op: Fetch{}}
	d := p.Decide(req)
	other, _ := ParseRepoGlob("acme/*")
	d.Grant.Repos[0] = other
	d.Grant.Access = AccessRead
	if g := p.grants["rpi01-agent"][0]; g.Repos[0].String() != "bolaum/*" || g.Access != AccessWrite {
		t.Errorf("changing a decision's grant changed the policy: %+v", g)
	}
}
