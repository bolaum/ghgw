package core

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// User is an identity that calls the gateway, usually an agent.
type User struct {
	Name     string
	Disabled bool
}

// Group is a named set of users; its grants apply to all members.
type Group struct {
	Name    string
	Members []string
}

// HolderKind says whether a grant belongs to a user or a group.
type HolderKind int

const (
	HolderUser HolderKind = iota + 1
	HolderGroup
)

// Holder is the user or group a grant is attached to.
type Holder struct {
	Kind HolderKind
	Name string
}

// String reads as "user rpi01-agent" or "group agents", as in decision reasons.
func (h Holder) String() string {
	name := Printable(h.Name)
	switch h.Kind {
	case HolderUser:
		return "user " + name
	case HolderGroup:
		return "group " + name
	}
	return "holder " + name
}

// Access is the git access a grant gives.
type Access string

const (
	// AccessRead allows fetch and clone.
	AccessRead Access = "read"
	// AccessWrite allows fetch, clone and pushes to the grant's push branches.
	AccessWrite Access = "write"
)

// Preset names the REST operations a grant allows. Presets are cumulative: pr includes read.
// The empty preset allows no REST operation.
type Preset string

const (
	PresetNone Preset = ""
	PresetRead Preset = "read"
	PresetPR   Preset = "pr"
)

func (p Preset) String() string {
	if p == PresetNone {
		return "none"
	}
	return string(p)
}

// MaxGrantPatterns bounds the repository patterns and the push patterns of a grant, so a policy
// (and every decision built from it) stays small whatever the admin sends. Each pattern's length
// is bounded by its parser.
const MaxGrantPatterns = 100

// Grant allows a set of repositories. Access governs git; API governs REST, independently, so a
// review agent can have read access and the pr preset.
type Grant struct {
	// ID identifies the grant across the whole policy; reasons cite it ("grant 2 of group agents")
	// so the admin can find and remove it.
	ID     int
	Holder Holder
	Repos  []RepoGlob
	Access Access
	// Push lists the branches that may be pushed with write access; empty means no push.
	Push []BranchGlob
	API  Preset
}

// String reads as "grant 2 of group agents".
func (g Grant) String() string { return g.identity().String() }

func (g Grant) identity() GrantIdentity { return GrantIdentity{ID: g.ID, Holder: g.Holder} }

// GrantIdentity is how a decision cites a grant: enough to name it and find it, and a value, so
// a decision never shares or copies the grant's patterns.
type GrantIdentity struct {
	ID     int
	Holder Holder
}

// String reads as "grant 2 of group agents".
func (g GrantIdentity) String() string {
	return fmt.Sprintf("grant %d of %s", g.ID, g.Holder)
}

func (g Grant) matches(r Repo) bool {
	return slices.ContainsFunc(g.Repos, func(p RepoGlob) bool { return p.Match(r) })
}

func (g Grant) clone() *Grant {
	g.Repos = slices.Clone(g.Repos)
	g.Push = slices.Clone(g.Push)
	return &g
}

// State is everything a Policy is built from, as plain data: the store loads it, tests write it
// inline.
type State struct {
	Users  []User
	Groups []Group
	Grants []Grant
	// Owners lists the GitHub owners that have a credential.
	Owners []string
}

// Policy is a validated State, read-only and safe for concurrent use. It decides requests.
type Policy struct {
	users map[string]User
	// groups holds each user's groups, ordered by name.
	groups map[string][]string
	// grants holds each user's effective grants, ordered by ID.
	grants map[string][]*Grant
	// owners holds the lowercased names of the owners that have a credential.
	owners map[string]bool
	rest   *RESTTable
}

// NewPolicy validates s and builds a Policy from a copy of it that classifies REST calls with
// rest (nil: no REST operation is known). The error lists every problem.
func NewPolicy(s State, rest *RESTTable) (*Policy, error) {
	p := &Policy{
		rest:   rest,
		users:  make(map[string]User, len(s.Users)),
		groups: make(map[string][]string, len(s.Users)),
		grants: make(map[string][]*Grant, len(s.Users)),
		owners: make(map[string]bool, len(s.Owners)),
	}
	var errs []error
	for _, u := range s.Users {
		if err := checkPrincipalName("user", u.Name); err != nil {
			errs = append(errs, err)
			continue
		}
		if _, dup := p.users[u.Name]; dup {
			errs = append(errs, fmt.Errorf("user %s is defined twice", Printable(u.Name)))
			continue
		}
		p.users[u.Name] = u
	}

	members := make(map[string][]string, len(s.Groups))
	for _, g := range s.Groups {
		if err := checkPrincipalName("group", g.Name); err != nil {
			errs = append(errs, err)
			continue
		}
		if _, dup := members[g.Name]; dup {
			errs = append(errs, fmt.Errorf("group %s is defined twice", Printable(g.Name)))
			continue
		}
		members[g.Name] = []string{}
		for _, m := range g.Members {
			switch _, ok := p.users[m]; {
			case !ok:
				errs = append(errs, fmt.Errorf("group %s: member %s is not a user; create the user first", Printable(g.Name), Printable(m)))
			case slices.Contains(members[g.Name], m):
				errs = append(errs, fmt.Errorf("group %s: member %s is listed twice", Printable(g.Name), Printable(m)))
			default:
				members[g.Name] = append(members[g.Name], m)
				p.groups[m] = append(p.groups[m], g.Name)
			}
		}
	}
	for _, gs := range p.groups {
		slices.Sort(gs)
	}

	ids := make(map[int]bool, len(s.Grants))
	for _, g := range s.Grants {
		if err := checkGrant(g, p.users, members); err != nil {
			errs = append(errs, err)
			continue
		}
		if ids[g.ID] {
			errs = append(errs, fmt.Errorf("grant %d is defined twice", g.ID))
			continue
		}
		ids[g.ID] = true
		holders := members[g.Holder.Name]
		if g.Holder.Kind == HolderUser {
			holders = []string{g.Holder.Name}
		}
		c := g.clone()
		for _, u := range holders {
			p.grants[u] = append(p.grants[u], c)
		}
	}
	for _, gs := range p.grants {
		slices.SortFunc(gs, func(a, b *Grant) int { return cmp.Compare(a.ID, b.ID) })
	}

	for _, o := range s.Owners {
		if err := CheckOwnerName(o); err != nil {
			errs = append(errs, err)
			continue
		}
		key := strings.ToLower(o)
		if p.owners[key] {
			errs = append(errs, fmt.Errorf("owner %s is defined twice", Printable(o)))
			continue
		}
		p.owners[key] = true
	}

	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return p, nil
}

// ParseGrant builds a grant from the patterns an admin writes. The error lists every problem the
// grant has on its own, one per line; NewPolicy checks the ID and what depends on the rest of the
// policy.
func ParseGrant(id int, holder Holder, repos []string, access Access, push []string, api Preset) (Grant, error) {
	g := Grant{ID: id, Holder: holder, Access: access, API: api}
	var errs []error
	for _, s := range repos {
		r, err := ParseRepoGlob(s)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		g.Repos = append(g.Repos, r)
	}
	for _, s := range push {
		b, err := ParseBranchGlob(s)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		g.Push = append(g.Push, b)
	}
	// The counts are those written, so a pattern that failed to parse is not also reported missing.
	errs = append(errs, fieldProblems(g, len(repos), len(push))...)
	return g, grantErr(g, errs)
}

func checkGrant(g Grant, users map[string]User, groups map[string][]string) error {
	if g.ID <= 0 {
		return fmt.Errorf("grant %d: the ID must be positive", g.ID)
	}
	var errs []error
	var known bool
	switch g.Holder.Kind {
	case HolderUser:
		_, known = users[g.Holder.Name]
	case HolderGroup:
		_, known = groups[g.Holder.Name]
	default:
		return fmt.Errorf("%s: the holder must be a user or a group", g)
	}
	if !known {
		errs = append(errs, fmt.Errorf("%s does not exist; create it first", g.Holder))
	}
	errs = append(errs, fieldProblems(g, len(g.Repos), len(g.Push))...)
	if slices.ContainsFunc(g.Repos, func(r RepoGlob) bool { return r.name == nil }) {
		errs = append(errs, errors.New("has an empty repository pattern"))
	}
	if slices.ContainsFunc(g.Push, func(b BranchGlob) bool { return b.re == nil }) {
		errs = append(errs, errors.New("has an empty push pattern"))
	}
	return grantErr(g, errs)
}

// fieldProblems returns the problems of g's fields, for a grant written with repos repository
// patterns and push push patterns.
func fieldProblems(g Grant, repos, push int) []error {
	var errs []error
	switch {
	case repos == 0:
		errs = append(errs, errors.New("needs at least one repository pattern"))
	case repos > MaxGrantPatterns:
		errs = append(errs, fmt.Errorf("has %d repository patterns; a grant has at most %d", repos, MaxGrantPatterns))
	}
	switch g.Access {
	case AccessRead:
		if push > 0 {
			errs = append(errs, errors.New("push branches need access write"))
		}
	case AccessWrite:
	default:
		errs = append(errs, fmt.Errorf("access must be read or write, not %s", Printable(string(g.Access))))
	}
	if push > MaxGrantPatterns {
		errs = append(errs, fmt.Errorf("has %d push patterns; a grant has at most %d", push, MaxGrantPatterns))
	}
	switch g.API {
	case PresetNone, PresetRead, PresetPR:
	default:
		errs = append(errs, fmt.Errorf("api must be read or pr (or empty for none), not %s", Printable(string(g.API))))
	}
	return errs
}

// grantErr joins errs, each prefixed with the grant ("grant 2 of group agents: ...").
func grantErr(g Grant, errs []error) error {
	for i, err := range errs {
		errs[i] = fmt.Errorf("%s: %w", g, err)
	}
	return errors.Join(errs...)
}
