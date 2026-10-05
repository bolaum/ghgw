package core

import (
	"fmt"
	"slices"
	"strings"
)

// Decision is the answer to a Request. Its reason is written for the agent that made the request
// and reads well after "ghgw: " (SPEC.md section 8).
type Decision struct {
	Allowed bool
	// Reason says which grant allowed the request, or what was denied, why, and what would work.
	// The guidance (allowed repositories or branches) appears here once, within renderBudget.
	Reason string
	// Grant is the grant that allowed the request. It is zero on denial, for operations allowed
	// for every user, and for pushes allowed by more than one grant (Refs then says which grant
	// allowed each ref).
	Grant GrantIdentity
	// Refs has one entry per ref update of a push, in order: the lines of the receive-pack report.
	// A push over MaxRefUpdates is rejected as a whole and has none.
	Refs []RefDecision
	// Operation is the REST operation a RESTRequest was classified as, allowed or not; empty when
	// it matched none or was denied before the table was consulted.
	Operation string
}

// RefDecision is the decision on one ref update of a push.
type RefDecision struct {
	// Ref is the ref exactly as the client sent it, for identity. It may hold any bytes: never
	// render it as is (Decision.String quotes it when needed).
	Ref     string
	Allowed bool
	// Reason is short and specific to the ref; the guidance is only in the decision's reason.
	Reason string
	Grant  GrantIdentity
}

// The limits bound the work and memory of a push decision whatever the client sends; a transport
// should enforce them while parsing, before it holds the updates in memory.
const (
	MaxRefUpdates = 1000
	MaxRefNameLen = 1024
)

// denial is why a request is denied: a short reason, and guidance that the decision's reason
// carries once (each ref of a push gets the short reason only).
type denial struct {
	reason, guidance string
}

func denialf(format string, args ...any) *denial {
	return &denial{reason: fmt.Sprintf(format, args...)}
}

// Decide decides r. Checks run from the most fundamental to the most specific, so the reason is
// the first thing the agent has to change: the user, then access to the repository, then the hard
// rules and the grants for the operation, then the owner's credential.
func (p *Policy) Decide(r Request) Decision {
	if why := p.checkUser(r.User); why != nil {
		return deny(r, why)
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
		if rest, ok := p.rest.lookup(op.Name); ok {
			d = p.decideOperation(r, rest, grants)
		} else {
			d = deny(r, denialf("unknown operation %s; ghgw only forwards the API operations it knows", Printable(op.Name)))
		}
	case RESTRequest:
		d = p.decideRESTRequest(r, op, grants)
	default:
		return deny(r, denialf("unknown operation"))
	}
	if d.Allowed && !r.Repo.IsZero() && !p.owners[strings.ToLower(r.Repo.Owner())] {
		return deny(r, denialf("ghgw has no credential for owner %s; ask the admin to add one", Printable(r.Repo.Owner())))
	}
	return d
}

// checkUser returns why user may do nothing (unknown or disabled), or nil.
func (p *Policy) checkUser(user string) *denial {
	switch u, ok := p.users[user]; {
	case !ok:
		return denialf("unknown user %s; ask the admin to create it", Printable(user))
	case u.Disabled:
		return denialf("user %s is disabled; ask the admin to enable it", Printable(user))
	}
	return nil
}

func decideFetch(r Request, grants []*Grant) Decision {
	matching, why := matchRepo(r, grants)
	if why != nil {
		return deny(r, why)
	}
	return allow(matching[0])
}

func decidePushAccess(r Request, grants []*Grant) Decision {
	write, why := writeGrants(r, grants)
	if why != nil {
		return deny(r, why)
	}
	return allow(write[0])
}

func decidePush(r Request, push Push, grants []*Grant) Decision {
	write, why := writeGrants(r, grants)
	if why != nil {
		return deny(r, why)
	}
	// All fail closed: a parser or lookup failure upstream must not become an unchecked push.
	if len(push.Updates) == 0 {
		return deny(r, denialf("the push has no ref updates, so it cannot be checked"))
	}
	if len(push.Updates) > MaxRefUpdates {
		return deny(r, denialf("the push has %d ref updates, more than the %d allowed; push fewer refs at a time", len(push.Updates), MaxRefUpdates))
	}
	if checkRefName("refs/heads/"+push.DefaultBranch) != nil {
		return deny(r, denialf("the default branch of %s is unknown or invalid, so the push cannot be checked; try again", Printable(r.Repo.String())))
	}

	d := Decision{Allowed: true, Refs: make([]RefDecision, 0, len(push.Updates))}
	for _, u := range push.Updates {
		rd := decideRef(u, push.DefaultBranch, write)
		if !rd.Allowed && d.Allowed {
			d.Allowed, d.Reason = false, rd.Reason+"; allowed branches: "+allowedBranches(write)
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
	d.Reason = "allowed by " + boundedList(names)
	if len(used) == 1 {
		d.Grant = d.Refs[0].Grant
	}
	return d
}

// decideOperation decides a REST operation of the table.
func (p *Policy) decideOperation(r Request, op RESTOperation, grants []*Grant) Decision {
	// The class is recomputed so a misclassified entry still cannot allow a hard-rule operation.
	class := op.class()
	name := Printable(op.Name)
	switch class {
	case ClassUnscoped:
		return deny(r, denialf("%s is not allowed: %s", name, hardRules[class]))
	case ClassGlobal:
		if !r.Repo.IsZero() {
			return deny(r, denialf("%s is not repository-scoped; call it without a repository", name))
		}
		return Decision{Allowed: true, Reason: "allowed for every user"}
	}
	matching, why := matchRepo(r, grants)
	if why != nil {
		return deny(r, why)
	}
	if rule, hard := hardRules[class]; hard {
		return deny(r, denialf("%s is not allowed: %s", name, rule))
	}
	var have []string
	for _, g := range matching {
		if g.API.allows(class) {
			return allow(g)
		}
		have = append(have, fmt.Sprintf("%s (%s)", g.API, g))
	}
	return deny(r, &denial{
		reason:   fmt.Sprintf("%s on %s needs API preset %s", name, Printable(r.Repo.String()), presetFor(class)),
		guidance: fmt.Sprintf("; %s has: %s", Printable(r.User), boundedList(have)),
	})
}

// decideRef applies the push rules of SPEC.md section 5.2 to one ref update. Its reason names only
// the ref's own problem; the push's reason adds the allowed branches once.
func decideRef(u RefUpdate, defaultBranch string, write []*Grant) RefDecision {
	deny := func(format string, args ...any) RefDecision {
		return RefDecision{Ref: u.Ref, Reason: fmt.Sprintf(format, args...)}
	}
	if len(u.Ref) > MaxRefNameLen {
		return deny("ref name is %d bytes, longer than the %d allowed", len(u.Ref), MaxRefNameLen)
	}
	if err := checkRefName(u.Ref); err != nil {
		return deny("invalid ref name %s: %v", Printable(u.Ref), err)
	}
	if u.Kind < CreateRef || u.Kind > DeleteRef {
		return deny("unknown update of %s", Printable(u.Ref))
	}
	branch, isBranch := strings.CutPrefix(u.Ref, "refs/heads/")
	switch {
	case strings.HasPrefix(u.Ref, "refs/tags/"):
		return deny("pushing tags is not allowed")
	case !isBranch:
		return deny("pushing %s is not allowed, only branches can be pushed", Printable(u.Ref))
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
				return RefDecision{Ref: u.Ref, Allowed: true, Reason: "allowed by " + g.String(), Grant: g.identity()}
			}
		}
	}
	if u.Kind == DeleteRef {
		return deny("deleting branch %s is not allowed", Printable(branch))
	}
	return deny("push to branch %s is not allowed", Printable(branch))
}

// matchRepo returns the grants that match the request's repository, or why there are none.
func matchRepo(r Request, grants []*Grant) ([]*Grant, *denial) {
	if r.Repo.IsZero() {
		return nil, denialf("%s needs a repository", Printable(r.Op.operation()))
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
				repos = append(repos, rg.String())
			}
		}
		return nil, &denial{
			reason:   fmt.Sprintf("%s cannot access %s", Printable(r.User), Printable(r.Repo.String())),
			guidance: ". Repositories allowed: " + boundedList(dedupe(repos)),
		}
	}
	return matching, nil
}

// writeGrants returns the grants with write access that match the request's repository, or why
// there are none.
func writeGrants(r Request, grants []*Grant) ([]*Grant, *denial) {
	matching, why := matchRepo(r, grants)
	if why != nil {
		return nil, why
	}
	var write []*Grant
	for _, g := range matching {
		if g.Access == AccessWrite {
			write = append(write, g)
		}
	}
	if len(write) == 0 {
		return nil, denialf("%s has read-only access to %s; pushing needs a grant with access write", Printable(r.User), Printable(r.Repo.String()))
	}
	return write, nil
}

func allowedBranches(grants []*Grant) string {
	var branches []string
	for _, g := range grants {
		for _, b := range g.Push {
			branches = append(branches, b.String())
		}
	}
	return boundedList(dedupe(branches))
}

// dedupe drops repeated items in place, keeping the first of each in order.
func dedupe(items []string) []string {
	seen := make(map[string]bool, len(items))
	out := items[:0]
	for _, s := range items {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func allow(g *Grant) Decision {
	return Decision{Allowed: true, Reason: "allowed by " + g.String(), Grant: g.identity()}
}

// deny denies the whole request: the decision's reason carries the guidance, each ref of a push
// the short reason only. A push over MaxRefUpdates gets no per-ref entries at all, so rejecting it
// costs nothing per update whatever the path (unknown user, no access, too many updates).
func deny(r Request, why *denial) Decision {
	d := Decision{Reason: why.reason + why.guidance}
	if push, ok := r.Op.(Push); ok && len(push.Updates) <= MaxRefUpdates {
		d.Refs = make([]RefDecision, len(push.Updates))
		for i, u := range push.Updates {
			d.Refs[i] = RefDecision{Ref: u.Ref, Reason: why.reason}
		}
	}
	return d
}

// String renders the decision for explain: the decision and its reason, then one line per ref of
// a push.
func (d Decision) String() string {
	lines := []string{verdict(d.Allowed, d.Reason)}
	for _, rd := range d.Refs {
		lines = append(lines, "  "+Printable(rd.Ref)+": "+verdict(rd.Allowed, rd.Reason))
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
