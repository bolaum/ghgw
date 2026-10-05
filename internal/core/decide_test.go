package core

import (
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"unicode"
	"unicode/utf8"
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
			{Name: "wide"},
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
			grant(t, 8, "user wide", bolaum, AccessWrite, []string{"**"}, PresetPR),
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
			d := p.Decide(Request{User: tt.user, Repo: repo, Op: tt.op})
			if got := summarize(d); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Decide() =\n%+v\nwant\n%+v", got, tt.want)
			}
			checkSafeExplain(t, d)
		})
	}
}

// checkSafeExplain checks that explain output has exactly one line for the decision and one per
// ref, made of printable characters only, whatever bytes the request carried.
func checkSafeExplain(t *testing.T, d Decision) {
	t.Helper()
	out := d.String()
	lines := strings.Split(out, "\n")
	if len(lines) != 1+len(d.Refs) {
		t.Errorf("String() has %d lines, want %d:\n%s", len(lines), 1+len(d.Refs), out)
	}
	for _, line := range lines {
		if !utf8.ValidString(line) || strings.ContainsFunc(line, func(c rune) bool { return !unicode.IsPrint(c) }) {
			t.Errorf("String() line %q has unprintable characters", line)
		}
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
			name: "no updates fails closed",
			user: "wide", repo: "bolaum/ghgw", op: Push{DefaultBranch: "main"},
			want: result{Reason: "the push has no ref updates, so it cannot be checked"},
		},
		{
			name: "unknown default branch",
			user: "rpi01-agent", repo: "bolaum/ghgw", op: Push{Updates: []RefUpdate{create(agentX)}},
			want: deniedPush("the default branch of bolaum/ghgw is unknown or invalid, so the push cannot be checked; try again",
				deniedRef(agentX, "the default branch of bolaum/ghgw is unknown or invalid, so the push cannot be checked; try again")),
		},
		{
			name: "default branch that is not a branch name",
			user: "wide", repo: "bolaum/ghgw", op: Push{DefaultBranch: " ", Updates: []RefUpdate{update(main)}},
			want: deniedPush("the default branch of bolaum/ghgw is unknown or invalid, so the push cannot be checked; try again",
				deniedRef(main, "the default branch of bolaum/ghgw is unknown or invalid, so the push cannot be checked; try again")),
		},
		{
			name: "default branch with an invalid sequence",
			user: "wide", repo: "bolaum/ghgw", op: Push{DefaultBranch: "a..b", Updates: []RefUpdate{update(agentX)}},
			want: deniedPush("the default branch of bolaum/ghgw is unknown or invalid, so the push cannot be checked; try again",
				deniedRef(agentX, "the default branch of bolaum/ghgw is unknown or invalid, so the push cannot be checked; try again")),
		},
		{
			name: "no repository",
			user: "rpi01-agent", op: Push{DefaultBranch: "main", Updates: []RefUpdate{create(agentX)}},
			want: deniedPush("push needs a repository", deniedRef(agentX, "push needs a repository")),
		},
	})
}

func TestDecidePushAccess(t *testing.T) {
	runDecideTests(t, testPolicy(t), []decideTest{
		{
			name: "write access",
			user: "rpi01-agent", repo: "bolaum/ghgw", op: PushAccess{},
			want: allowedBy(1, "group agents"),
		},
		{
			name: "write access without push branches still answers yes",
			user: "nopush", repo: "bolaum/ghgw", op: PushAccess{},
			want: allowedBy(7, "user nopush"),
		},
		{
			name: "read-only access",
			user: "reviewer", repo: "bolaum/ghgw", op: PushAccess{},
			want: result{Reason: "reviewer has read-only access to bolaum/ghgw; pushing needs a grant with access write"},
		},
		{
			name: "repository not granted",
			user: "rpi01-agent", repo: "acme/secret", op: PushAccess{},
			want: result{Reason: "rpi01-agent cannot access acme/secret. Repositories allowed: bolaum/*, nocred/app"},
		},
		{
			name: "owner without credential",
			user: "rpi01-agent", repo: "nocred/app", op: PushAccess{},
			want: result{Reason: "ghgw has no credential for owner nocred; ask the admin to add one"},
		},
		{
			name: "no repository",
			user: "rpi01-agent", op: PushAccess{},
			want: result{Reason: "push needs a repository"},
		},
	})
}

// TestDecidePushHardRules pushes with a grant whose push glob is "**": the hard rules and the ref
// name rules still deny, and no grant is cited.
func TestDecidePushHardRules(t *testing.T) {
	const all = "; allowed branches: **"
	denied := func(ref, reason string) result {
		return result{Reason: reason + all, Refs: []refResult{{Ref: ref, Reason: reason + all}}}
	}
	notBranch := func(ref string) result {
		return denied(ref, "pushing "+ref+" is not allowed, only branches can be pushed")
	}
	invalid := func(ref, why string) result {
		return denied(ref, fmt.Sprintf("invalid ref name %q: %s", ref, why))
	}
	push := func(u RefUpdate) Push { return Push{DefaultBranch: "main", Updates: []RefUpdate{u}} }
	injected := "refs/heads/agent/x\nallowed by grant 1 of group agents\n\x1b[2J"
	bidi := "refs/heads/agent/\u202egnp.exe"

	runDecideTests(t, testPolicy(t), []decideTest{
		{name: "allowed branch", user: "wide", repo: "bolaum/ghgw", op: push(create("refs/heads/x")),
			want: result{Allowed: true, Reason: "allowed by grant 8 of user wide", Grant: 8,
				Refs: []refResult{{Ref: "refs/heads/x", Allowed: true, Reason: "allowed by grant 8 of user wide", Grant: 8}}}},
		{name: "default branch", user: "wide", repo: "bolaum/ghgw", op: push(update("refs/heads/main")),
			want: denied("refs/heads/main", "push to the default branch is not allowed")},
		{name: "HEAD", user: "wide", repo: "bolaum/ghgw", op: push(update("HEAD")), want: notBranch("HEAD")},
		{name: "pull request ref", user: "wide", repo: "bolaum/ghgw", op: push(update("refs/pull/1/head")),
			want: notBranch("refs/pull/1/head")},
		{name: "remote-tracking ref", user: "wide", repo: "bolaum/ghgw", op: push(update("refs/remotes/origin/main")),
			want: notBranch("refs/remotes/origin/main")},
		{name: "tag create", user: "wide", repo: "bolaum/ghgw", op: push(create("refs/tags/v1")),
			want: denied("refs/tags/v1", "pushing tags is not allowed")},
		{name: "tag update", user: "wide", repo: "bolaum/ghgw", op: push(update("refs/tags/v1")),
			want: denied("refs/tags/v1", "pushing tags is not allowed")},
		{name: "tag delete", user: "wide", repo: "bolaum/ghgw", op: push(remove("refs/tags/v1")),
			want: denied("refs/tags/v1", "pushing tags is not allowed")},
		{name: "star", user: "wide", repo: "bolaum/ghgw", op: push(create("refs/heads/a*b")),
			want: invalid("refs/heads/a*b", "cannot contain '*'")},
		{name: "NUL", user: "wide", repo: "bolaum/ghgw", op: push(create("refs/heads/a\x00b")),
			want: invalid("refs/heads/a\x00b", `cannot contain '\x00'`)},
		{name: "newline", user: "wide", repo: "bolaum/ghgw", op: push(create("refs/heads/a\nb")),
			want: invalid("refs/heads/a\nb", `cannot contain '\n'`)},
		{name: "DEL", user: "wide", repo: "bolaum/ghgw", op: push(create("refs/heads/a\x7fb")),
			want: invalid("refs/heads/a\x7fb", `cannot contain '\x7f'`)},
		{name: "invalid UTF-8", user: "wide", repo: "bolaum/ghgw", op: push(create("refs/heads/\xff")),
			want: invalid("refs/heads/\xff", "not valid UTF-8")},
		{name: "hidden component", user: "wide", repo: "bolaum/ghgw", op: push(create("refs/heads/.hidden")),
			want: invalid("refs/heads/.hidden", `no part between slashes can start with '.' or end with ".lock"`)},
		{name: "lock component", user: "wide", repo: "bolaum/ghgw", op: push(create("refs/heads/x.lock")),
			want: invalid("refs/heads/x.lock", `no part between slashes can start with '.' or end with ".lock"`)},
		{name: "double slash", user: "wide", repo: "bolaum/ghgw", op: push(create("refs/heads/a//b")),
			want: invalid("refs/heads/a//b", `cannot end with '/' or contain "//"`)},
		{name: "trailing slash", user: "wide", repo: "bolaum/ghgw", op: push(create("refs/heads/a/")),
			want: invalid("refs/heads/a/", `cannot end with '/' or contain "//"`)},
		{name: "trailing dot", user: "wide", repo: "bolaum/ghgw", op: push(create("refs/heads/a.")),
			want: invalid("refs/heads/a.", "cannot end with '.'")},
		{name: "forged explain lines", user: "wide", repo: "bolaum/ghgw", op: push(create(injected)),
			want: invalid(injected, `cannot contain '\n'`)},
		{name: "invisible characters are allowed but quoted", user: "wide", repo: "bolaum/ghgw", op: push(create(bidi)),
			want: result{Allowed: true, Reason: "allowed by grant 8 of user wide", Grant: 8,
				Refs: []refResult{{Ref: bidi, Allowed: true, Reason: "allowed by grant 8 of user wide", Grant: 8}}}},
	})

	d := testPolicy(t).Decide(Request{User: "wide", Repo: mustRepo(t, "bolaum/ghgw"), Op: push(create(injected))})
	want := `denied: invalid ref name "refs/heads/agent/x\nallowed by grant 1 of group agents\n\x1b[2J": cannot contain '\n'; allowed branches: **` + "\n" +
		`  "refs/heads/agent/x\nallowed by grant 1 of group agents\n\x1b[2J": denied: invalid ref name "refs/heads/agent/x\nallowed by grant 1 of group agents\n\x1b[2J": cannot contain '\n'; allowed branches: **`
	if got := d.String(); got != want {
		t.Errorf("String() =\n%s\nwant\n%s", got, want)
	}
	d = testPolicy(t).Decide(Request{User: "wide", Repo: mustRepo(t, "bolaum/ghgw"), Op: push(create(bidi))})
	if got, want := d.String(), "allowed by grant 8 of user wide\n  \"refs/heads/agent/\\u202egnp.exe\": allowed by grant 8 of user wide"; got != want {
		t.Errorf("String() =\n%s\nwant\n%s", got, want)
	}
}

// TestDecidePushAllOrNothing mixes an allowed and a forbidden update in both orders: the whole push
// is denied and no ref keeps a grant.
func TestDecidePushAllOrNothing(t *testing.T) {
	const (
		agentX  = "refs/heads/agent/x"
		tag     = "refs/tags/v1"
		tagDeny = "pushing tags is not allowed; allowed branches: agent/**"
		another = "another ref was rejected"
		noCred  = "ghgw has no credential for owner nocred; ask the admin to add one"
	)
	push := func(us ...RefUpdate) Push { return Push{DefaultBranch: "main", Updates: us} }
	runDecideTests(t, testPolicy(t), []decideTest{
		{name: "allowed first", user: "rpi01-agent", repo: "bolaum/ghgw", op: push(create(agentX), create(tag)),
			want: result{Reason: tagDeny, Refs: []refResult{{Ref: agentX, Reason: another}, {Ref: tag, Reason: tagDeny}}}},
		{name: "forbidden first", user: "rpi01-agent", repo: "bolaum/ghgw", op: push(create(tag), create(agentX)),
			want: result{Reason: tagDeny, Refs: []refResult{{Ref: tag, Reason: tagDeny}, {Ref: agentX, Reason: another}}}},
		{name: "allowed first, no credential", user: "rpi01-agent", repo: "nocred/app", op: push(create(agentX), create(tag)),
			want: result{Reason: tagDeny, Refs: []refResult{{Ref: agentX, Reason: another}, {Ref: tag, Reason: tagDeny}}}},
		{name: "forbidden first, no credential", user: "rpi01-agent", repo: "nocred/app", op: push(create(tag), create(agentX)),
			want: result{Reason: tagDeny, Refs: []refResult{{Ref: tag, Reason: tagDeny}, {Ref: agentX, Reason: another}}}},
		{name: "all allowed, no credential", user: "rpi01-agent", repo: "nocred/app", op: push(create(agentX), update("refs/heads/agent/y")),
			want: result{Reason: noCred, Refs: []refResult{{Ref: agentX, Reason: noCred}, {Ref: "refs/heads/agent/y", Reason: noCred}}}},
	})
}

// TestDecideLowestGrantID lists overlapping own and group grants out of ID order: the lowest ID
// that allows the request is cited, for every kind of operation and for each ref.
func TestDecideLowestGrantID(t *testing.T) {
	p, err := NewPolicy(State{
		Users:  []User{{Name: "u"}},
		Groups: []Group{{Name: "g", Members: []string{"u"}}},
		Grants: []Grant{
			grant(t, 9, "user u", []string{"bolaum/*"}, AccessWrite, []string{"**"}, PresetPR),
			grant(t, 5, "user u", []string{"bolaum/app"}, AccessWrite, []string{"**"}, PresetRead),
			grant(t, 3, "group g", []string{"bolaum/app"}, AccessWrite, []string{"agent/**"}, PresetPR),
		},
		Owners: []string{"bolaum"},
	}, testRESTTable(t))
	if err != nil {
		t.Fatal(err)
	}
	push := func(us ...RefUpdate) Push { return Push{DefaultBranch: "main", Updates: us} }
	runDecideTests(t, p, []decideTest{
		{name: "fetch", user: "u", repo: "bolaum/app", op: Fetch{}, want: allowedBy(3, "group g")},
		{name: "fetch, one grant matches", user: "u", repo: "bolaum/other", op: Fetch{}, want: allowedBy(9, "user u")},
		{name: "push access", user: "u", repo: "bolaum/app", op: PushAccess{}, want: allowedBy(3, "group g")},
		{name: "rest read", user: "u", repo: "bolaum/app", op: REST{Name: "pulls.list"}, want: allowedBy(3, "group g")},
		{name: "rest pr", user: "u", repo: "bolaum/app", op: REST{Name: "pulls.create"}, want: allowedBy(3, "group g")},
		{
			name: "each ref", user: "u", repo: "bolaum/app",
			op: push(create("refs/heads/feature/x"), create("refs/heads/agent/x")),
			want: result{
				Allowed: true,
				Reason:  "allowed by grant 5 of user u, grant 3 of group g",
				Refs: []refResult{
					{Ref: "refs/heads/feature/x", Allowed: true, Reason: "allowed by grant 5 of user u", Grant: 5},
					{Ref: "refs/heads/agent/x", Allowed: true, Reason: "allowed by grant 3 of group g", Grant: 3},
				},
			},
		},
	})
}

// TestDecideDoesNotDiscloseCredentials asks for repositories the user has no grant for: whether
// their owner has a credential does not change the answer.
func TestDecideDoesNotDiscloseCredentials(t *testing.T) {
	p := testPolicy(t)
	for _, op := range []Operation{Fetch{}, PushAccess{}, REST{Name: "pulls.list"}} {
		withCred := p.Decide(Request{User: "rpi01-agent", Repo: mustRepo(t, "acme/secret"), Op: op})
		withoutCred := p.Decide(Request{User: "rpi01-agent", Repo: mustRepo(t, "nocred/secret"), Op: op})
		got := strings.Replace(withoutCred.Reason, "nocred/secret", "acme/secret", 1)
		if withCred.Allowed || withoutCred.Allowed || got != withCred.Reason {
			t.Errorf("%T: with a credential %q, without %q; want the same denial", op, withCred.Reason, withoutCred.Reason)
		}
	}
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

	t.Run("hard rules override a misclassified table", func(t *testing.T) {
		// Built by hand: NewRESTTable rejects every one of these entries.
		table := &RESTTable{byName: map[string]RESTOperation{}}
		for _, op := range []RESTOperation{
			{Name: "contents.update", Method: "PUT", Path: "/repos/{owner}/{repo}/contents/{path}", Class: ClassPR},
			{Name: "pulls.merge", Method: "PUT", Path: "/repos/{owner}/{repo}/pulls/{pull_number}/merge", Class: ClassPR},
			{Name: "hooks.list", Method: "GET", Path: "/repos/{owner}/{repo}/hooks", Class: ClassRead},
			{Name: "users.get", Method: "GET", Path: "/user", Class: ClassGlobal},
		} {
			table.byName[op.Name] = op
		}
		p, err := NewPolicy(State{
			Users:  []User{{Name: "a"}},
			Grants: []Grant{grant(t, 1, "user a", []string{"bolaum/*"}, AccessWrite, []string{"**"}, PresetPR)},
			Owners: []string{"bolaum"},
		}, table)
		if err != nil {
			t.Fatal(err)
		}
		runDecideTests(t, p, []decideTest{
			{name: "contents write in a preset", user: "a", repo: "bolaum/x", op: REST{Name: "contents.update"},
				want: result{Reason: "contents.update is not allowed: " + codeChange}},
			{name: "merge in a preset", user: "a", repo: "bolaum/x", op: REST{Name: "pulls.merge"},
				want: result{Reason: "pulls.merge is not allowed: ghgw never merges pull requests; ask a person to merge"}},
			{name: "administration read in a preset", user: "a", repo: "bolaum/x", op: REST{Name: "hooks.list"},
				want: result{Reason: "hooks.list is not allowed: repository administration is not available through ghgw"}},
			{name: "unscoped endpoint as global", user: "a", op: REST{Name: "users.get"},
				want: result{Reason: "users.get is not allowed: only repository endpoints (repos/{owner}/{repo}/...), rate_limit and meta are available"}},
		})
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

func TestDecisionString(t *testing.T) {
	p := testPolicy(t)
	bolaum := mustRepo(t, "bolaum/ghgw")
	tests := []struct {
		name string
		req  Request
		want string
	}{
		{
			name: "allowed",
			req:  Request{User: "rpi01-agent", Repo: bolaum, Op: Fetch{}},
			want: "allowed by grant 1 of group agents",
		},
		{
			name: "denied",
			req:  Request{User: "lonely", Repo: bolaum, Op: Fetch{}},
			want: "denied: lonely cannot access bolaum/ghgw. Repositories allowed: none",
		},
		{
			name: "allowed push",
			req: Request{User: "rpi01-agent", Repo: bolaum, Op: Push{DefaultBranch: "main", Updates: []RefUpdate{
				create("refs/heads/agent/x"), remove("refs/heads/agent/y"),
			}}},
			want: "allowed by grant 1 of group agents\n" +
				"  refs/heads/agent/x: allowed by grant 1 of group agents\n" +
				"  refs/heads/agent/y: allowed by grant 1 of group agents",
		},
		{
			name: "denied push",
			req: Request{User: "rpi01-agent", Repo: bolaum, Op: Push{DefaultBranch: "main", Updates: []RefUpdate{
				create("refs/heads/agent/x"), update("refs/heads/main"),
			}}},
			want: "denied: push to the default branch is not allowed; allowed branches: agent/**\n" +
				"  refs/heads/agent/x: denied: another ref was rejected\n" +
				"  refs/heads/main: denied: push to the default branch is not allowed; allowed branches: agent/**",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := p.Decide(tt.req).String(); got != tt.want {
				t.Errorf("String() =\n%s\nwant\n%s", got, tt.want)
			}
		})
	}
}

// TestPolicyImmutable changes everything a policy was built from and everything a decision
// returns, while deciding concurrently (run with -race): decisions do not change.
func TestPolicyImmutable(t *testing.T) {
	s := State{
		Users:  []User{{Name: "a"}, {Name: "b"}},
		Groups: []Group{{Name: "g", Members: []string{"a"}}},
		Grants: []Grant{
			grant(t, 1, "group g", []string{"bolaum/*"}, AccessWrite, []string{"agent/**"}, PresetRead),
			grant(t, 2, "user b", []string{"bolaum/x"}, AccessRead, nil, PresetRead),
		},
		Owners: []string{"bolaum"},
	}
	p, err := NewPolicy(s, testRESTTable(t))
	if err != nil {
		t.Fatal(err)
	}
	push := Request{User: "a", Repo: mustRepo(t, "bolaum/ghgw"), Op: Push{DefaultBranch: "main", Updates: []RefUpdate{create("refs/heads/agent/x")}}}
	fetch := Request{User: "b", Repo: mustRepo(t, "bolaum/x"), Op: Fetch{}}
	wantPush, wantFetch := summarize(p.Decide(push)), summarize(p.Decide(fetch))
	if !wantPush.Allowed || !wantFetch.Allowed {
		t.Fatalf("Decide() = %+v, %+v; want both allowed", wantPush, wantFetch)
	}

	other, _ := ParseRepoGlob("acme/*")
	feature, _ := ParseBranchGlob("feature/*")
	s.Users[0].Disabled = true
	s.Users[1].Name = "c"
	s.Groups[0].Members[0] = "b"
	s.Grants[0].Repos[0] = other
	s.Grants[0].Push[0] = feature
	s.Grants[0].Access = AccessRead
	s.Grants[1].API = PresetNone
	s.Owners[0] = "acme"

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 50 {
				d := p.Decide(push)
				if got := summarize(d); !reflect.DeepEqual(got, wantPush) {
					t.Errorf("Decide(push) = %+v, want %+v", got, wantPush)
					return
				}
				d.Grant.Push[0] = feature
				d.Grant.Repos[0] = other
				d.Refs[0].Grant.Push = nil
				d.Refs[0].Grant.Access = AccessRead
				if got := summarize(p.Decide(fetch)); !reflect.DeepEqual(got, wantFetch) {
					t.Errorf("Decide(fetch) = %+v, want %+v", got, wantFetch)
					return
				}
			}
		})
	}
	wg.Wait()
	if g := p.grants["a"][0]; g.Push[0].String() != "agent/**" || g.Repos[0].String() != "bolaum/*" || g.Access != AccessWrite {
		t.Errorf("the policy's grant changed: %+v", g)
	}
}
