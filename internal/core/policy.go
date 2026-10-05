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
	name := printable(h.Name)
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
			errs = append(errs, fmt.Errorf("user %s is defined twice", printable(u.Name)))
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
			errs = append(errs, fmt.Errorf("group %s is defined twice", printable(g.Name)))
			continue
		}
		members[g.Name] = []string{}
		for _, m := range g.Members {
			switch _, ok := p.users[m]; {
			case !ok:
				errs = append(errs, fmt.Errorf("group %s: member %s is not a user; create the user first", printable(g.Name), printable(m)))
			case slices.Contains(members[g.Name], m):
				errs = append(errs, fmt.Errorf("group %s: member %s is listed twice", printable(g.Name), printable(m)))
			default:
				members[g.Name] = append(members[g.Name], m)
			}
		}
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
		if err := checkOwnerName(o); err != nil {
			errs = append(errs, err)
			continue
		}
		key := strings.ToLower(o)
		if p.owners[key] {
			errs = append(errs, fmt.Errorf("owner %s is defined twice", printable(o)))
			continue
		}
		p.owners[key] = true
	}

	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return p, nil
}

func checkGrant(g Grant, users map[string]User, groups map[string][]string) error {
	if g.ID <= 0 {
		return fmt.Errorf("grant %d: the ID must be positive", g.ID)
	}
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
		return fmt.Errorf("%s: %s does not exist; create it first", g, g.Holder)
	}
	if len(g.Repos) == 0 {
		return fmt.Errorf("%s: needs at least one repository pattern", g)
	}
	for _, r := range g.Repos {
		if r.name == nil {
			return fmt.Errorf("%s: has an empty repository pattern", g)
		}
	}
	switch g.Access {
	case AccessRead:
		if len(g.Push) > 0 {
			return fmt.Errorf("%s: push branches need access write", g)
		}
	case AccessWrite:
	default:
		return fmt.Errorf("%s: access must be read or write, not %s", g, printable(string(g.Access)))
	}
	for _, b := range g.Push {
		if b.re == nil {
			return fmt.Errorf("%s: has an empty push pattern", g)
		}
	}
	switch g.API {
	case PresetNone, PresetRead, PresetPR:
	default:
		return fmt.Errorf("%s: api must be read or pr (or empty for none), not %s", g, printable(string(g.API)))
	}
	return nil
}
