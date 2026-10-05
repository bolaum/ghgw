package core

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Decision is the answer to a Request. Its reason is written for the agent that made the request
// and reads well after "ghgw: " (SPEC.md section 8).
type Decision struct {
	Allowed bool
	// Reason says which grant allowed the request, or what was denied, why, and what would work.
	Reason string
	// Grant is the grant that allowed the request. It is nil on denial, for operations allowed for
	// every user, and for pushes allowed by more than one grant (Refs then says which grant
	// allowed each ref).
	Grant *Grant
	// Refs has one entry per ref update of a push, in order: the lines of the receive-pack report.
	Refs []RefDecision
}

// RefDecision is the decision on one ref update of a push.
type RefDecision struct {
	// Ref is the ref exactly as the client sent it, for identity. It may hold any bytes: never
	// render it as is (Decision.String quotes it when needed).
	Ref     string
	Allowed bool
	Reason  string
	Grant   *Grant
}

// Decide decides r. Checks run from the most fundamental to the most specific, so the reason is
// the first thing the agent has to change: the user, then access to the repository, then the hard
// rules and the grants for the operation, then the owner's credential.
func (p *Policy) Decide(r Request) Decision {
	switch u, ok := p.users[r.User]; {
	case !ok:
		return deny(r, "unknown user %s; ask the admin to create it", printable(r.User))
	case u.Disabled:
		return deny(r, "user %s is disabled; ask the admin to enable it", r.User)
	}
	grants := p.grants[r.User]
	var d Decision
	switch op := r.Op.(type) {
	case Fetch:
		d = decideFetch(r, grants)
	case PushAccess:
		d = decidePushAccess(r, grants)
	case Push:
		d = decidePush(r, op, grants)
	case REST:
		d = p.decideREST(r, op, grants)
	default:
		return deny(r, "unknown operation")
	}
	if d.Allowed && !r.Repo.IsZero() && !p.owners[strings.ToLower(r.Repo.Owner())] {
		return deny(r, "ghgw has no credential for owner %s; ask the admin to add one", r.Repo.Owner())
	}
	return d
}

func decideFetch(r Request, grants []*Grant) Decision {
	matching, why := matchRepo(r, grants)
	if why != "" {
		return deny(r, "%s", why)
	}
	return allow(matching[0])
}

func decidePushAccess(r Request, grants []*Grant) Decision {
	write, why := writeGrants(r, grants)
	if why != "" {
		return deny(r, "%s", why)
	}
	return allow(write[0])
}

func decidePush(r Request, push Push, grants []*Grant) Decision {
	write, why := writeGrants(r, grants)
	if why != "" {
		return deny(r, "%s", why)
	}
	// Both fail closed: a parser or lookup failure upstream must not become an unchecked push.
	if len(push.Updates) == 0 {
		return deny(r, "the push has no ref updates, so it cannot be checked")
	}
	if checkRefName("refs/heads/"+push.DefaultBranch) != nil {
		return deny(r, "the default branch of %s is unknown or invalid, so the push cannot be checked; try again", r.Repo)
	}

	branches := allowedBranches(write)
	d := Decision{Allowed: true}
	for _, u := range push.Updates {
		rd := decideRef(u, push.DefaultBranch, write, branches)
		if !rd.Allowed && d.Allowed {
			d.Allowed, d.Reason = false, rd.Reason
		}
		d.Refs = append(d.Refs, rd)
	}
	if !d.Allowed {
		for i, rd := range d.Refs {
			if rd.Allowed {
				d.Refs[i] = RefDecision{Ref: rd.Ref, Reason: "another ref was rejected"}
			}
		}
		return d
	}

	var used []int
	var names []string
	for _, rd := range d.Refs {
		if !slices.Contains(used, rd.Grant.ID) {
			used = append(used, rd.Grant.ID)
			names = append(names, rd.Grant.String())
		}
	}
	d.Reason = "allowed by " + strings.Join(names, ", ")
	if len(used) == 1 {
		d.Grant = d.Refs[0].Grant
	}
	return d
}

// writeGrants returns the grants with write access that match the request's repository, or why
// there are none.
func writeGrants(r Request, grants []*Grant) ([]*Grant, string) {
	matching, why := matchRepo(r, grants)
	if why != "" {
		return nil, why
	}
	var write []*Grant
	for _, g := range matching {
		if g.Access == AccessWrite {
			write = append(write, g)
		}
	}
	if len(write) == 0 {
		return nil, fmt.Sprintf("%s has read-only access to %s; pushing needs a grant with access write", r.User, r.Repo)
	}
	return write, ""
}

func (p *Policy) decideREST(r Request, call REST, grants []*Grant) Decision {
	op, ok := p.rest.lookup(call.Name)
	if !ok {
		return deny(r, "unknown operation %q; ghgw only forwards the API operations it knows", call.Name)
	}
	// The class is recomputed so a misclassified entry still cannot allow a hard-rule operation.
	class := op.class()
	switch class {
	case ClassUnscoped:
		return deny(r, "%s is not allowed: %s", op.Name, hardRules[class])
	case ClassGlobal:
		if !r.Repo.IsZero() {
			return deny(r, "%s is not repository-scoped; call it without a repository", op.Name)
		}
		return Decision{Allowed: true, Reason: "allowed for every user"}
	}
	matching, why := matchRepo(r, grants)
	if why != "" {
		return deny(r, "%s", why)
	}
	if rule, hard := hardRules[class]; hard {
		return deny(r, "%s is not allowed: %s", op.Name, rule)
	}
	var have []string
	for _, g := range matching {
		if g.API.allows(class) {
			return allow(g)
		}
		have = append(have, fmt.Sprintf("%s (%s)", g.API, g))
	}
	return deny(r, "%s on %s needs API preset %s; %s has: %s",
		op.Name, r.Repo, presetFor(class), r.User, strings.Join(have, ", "))
}

// decideRef applies the push rules of SPEC.md section 5.2 to one ref update. branches lists the
// allowed branches for the reasons.
func decideRef(u RefUpdate, defaultBranch string, write []*Grant, branches string) RefDecision {
	deny := func(format string, args ...any) RefDecision {
		return RefDecision{Ref: u.Ref, Reason: fmt.Sprintf(format, args...) + "; allowed branches: " + branches}
	}
	if err := checkRefName(u.Ref); err != nil {
		return deny("invalid ref name %q: %v", u.Ref, err)
	}
	if u.Kind < CreateRef || u.Kind > DeleteRef {
		return deny("unknown update of %s", u.Ref)
	}
	branch, isBranch := strings.CutPrefix(u.Ref, "refs/heads/")
	switch {
	case strings.HasPrefix(u.Ref, "refs/tags/"):
		return deny("pushing tags is not allowed")
	case !isBranch:
		return deny("pushing %s is not allowed, only branches can be pushed", printable(u.Ref))
	// Case-insensitive on purpose: denying "MAIN" next to "main" costs nothing, and no upstream
	// quirk can then turn it into a push to the default branch.
	case strings.EqualFold(branch, defaultBranch) && u.Kind == DeleteRef:
		return deny("deleting the default branch is not allowed")
	case strings.EqualFold(branch, defaultBranch):
		return deny("push to the default branch is not allowed")
	}
	for _, g := range write {
		for _, b := range g.Push {
			if b.Match(branch) {
				return RefDecision{Ref: u.Ref, Allowed: true, Reason: "allowed by " + g.String(), Grant: g.clone()}
			}
		}
	}
	if u.Kind == DeleteRef {
		return deny("deleting branch %s is not allowed", printable(branch))
	}
	return deny("push to branch %s is not allowed", printable(branch))
}

// matchRepo returns the grants that match the request's repository, or why there are none.
func matchRepo(r Request, grants []*Grant) ([]*Grant, string) {
	if r.Repo.IsZero() {
		return nil, r.Op.operation() + " needs a repository"
	}
	var matching []*Grant
	for _, g := range grants {
		if g.matches(r.Repo) {
			matching = append(matching, g)
		}
	}
	if len(matching) == 0 {
		var repos []string
		for _, g := range grants {
			for _, rg := range g.Repos {
				if !slices.Contains(repos, rg.String()) {
					repos = append(repos, rg.String())
				}
			}
		}
		return nil, fmt.Sprintf("%s cannot access %s. Repositories allowed: %s", r.User, r.Repo, listOrNone(repos))
	}
	return matching, ""
}

func allowedBranches(grants []*Grant) string {
	var branches []string
	for _, g := range grants {
		for _, b := range g.Push {
			if s := printable(b.String()); !slices.Contains(branches, s) {
				branches = append(branches, s)
			}
		}
	}
	return listOrNone(branches)
}

func listOrNone(items []string) string {
	if len(items) == 0 {
		return "none"
	}
	return strings.Join(items, ", ")
}

func allow(g *Grant) Decision {
	return Decision{Allowed: true, Reason: "allowed by " + g.String(), Grant: g.clone()}
}

// deny denies the whole request; for a push, every ref gets the same reason.
func deny(r Request, format string, args ...any) Decision {
	d := Decision{Reason: fmt.Sprintf(format, args...)}
	if push, ok := r.Op.(Push); ok {
		for _, u := range push.Updates {
			d.Refs = append(d.Refs, RefDecision{Ref: u.Ref, Reason: d.Reason})
		}
	}
	return d
}

// String renders the decision for explain: the decision and its reason, then one line per ref of
// a push.
func (d Decision) String() string {
	lines := []string{verdict(d.Allowed, d.Reason)}
	for _, rd := range d.Refs {
		lines = append(lines, "  "+printable(rd.Ref)+": "+verdict(rd.Allowed, rd.Reason))
	}
	return strings.Join(lines, "\n")
}

// verdict prefixes denials only: reasons of allowed decisions already start with "allowed".
func verdict(allowed bool, reason string) string {
	if allowed {
		return reason
	}
	return "denied: " + reason
}

// printable returns s as is when it is valid UTF-8 made only of printable characters, and quoted
// in Go syntax (ASCII only) otherwise. Untrusted identifiers go through it before they are
// rendered, so they cannot add lines, terminal controls or invisible characters (bidi overrides,
// zero-width spaces) to a reason or to explain output.
func printable(s string) string {
	if s != "" && utf8.ValidString(s) && !strings.ContainsFunc(s, func(c rune) bool { return !unicode.IsPrint(c) }) {
		return s
	}
	return strconv.QuoteToASCII(s)
}
