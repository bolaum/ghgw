package core

import (
	"errors"
	"slices"
)

// Identity is a user as whoami shows it (SPEC.md section 5.5): its groups and what it may do.
type Identity struct {
	User   string
	Groups []string
	// Grants are the user's effective grants, its own and those of its groups, ordered by ID.
	Grants []Grant
}

// Identity returns the identity of user, or why it may do nothing (unknown or disabled) in a
// message that reads well after "ghgw: ".
func (p *Policy) Identity(user string) (Identity, error) {
	if why := p.checkUser(user); why != nil {
		return Identity{}, errors.New(why.reason)
	}
	id := Identity{User: user, Groups: slices.Clone(p.groups[user])}
	for _, g := range p.grants[user] {
		id.Grants = append(id.Grants, *g.clone())
	}
	return id, nil
}
