// Package core holds the domain of ghgw and its decisions: users, groups, grants, the hard rules
// and Decide. It does no HTTP and no storage; transports and the store build on it.
package core

import (
	"fmt"
	"regexp"
	"strings"
)

// The name rules are stricter than GitHub's where that costs nothing: a validated name can be put
// in an upstream URL path as is, so "..", "/" or "%" never reach GitHub from a decided request.
var (
	ownerNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$`)
	repoNameRE  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)
	// User and group names are lowercase so "Agent" and "agent" can never be two identities.
	principalNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
)

// Repo is a GitHub repository, owner/name. Names keep the case they were given in, for messages;
// GitHub compares them case-insensitively and so does every match in core.
// The zero Repo means "no repository" (for operations that are not repository-scoped).
type Repo struct {
	owner, name string
}

// ParseRepo parses "owner/name".
func ParseRepo(s string) (Repo, error) {
	owner, name, ok := strings.Cut(s, "/")
	if !ok {
		return Repo{}, fmt.Errorf("repository %q: want owner/name", s)
	}
	if err := checkOwnerName(owner); err != nil {
		return Repo{}, fmt.Errorf("repository %q: %w", s, err)
	}
	if !repoNameRE.MatchString(name) || name == "." || name == ".." {
		return Repo{}, fmt.Errorf("repository %q: name must be 1 to 100 letters, digits, '.', '-' or '_'", s)
	}
	if hasGitSuffix(name) {
		return Repo{}, fmt.Errorf("repository %q: write the name without the .git suffix", s)
	}
	return Repo{owner: owner, name: name}, nil
}

// hasGitSuffix reports whether a repository name ends in ".git". Such names are rejected: the
// transports treat the suffix as optional, so "x.git" must always mean repository "x".
func hasGitSuffix(name string) bool {
	return strings.HasSuffix(strings.ToLower(name), ".git")
}

// Owner returns the owner as given.
func (r Repo) Owner() string { return r.owner }

// IsZero reports whether r is "no repository".
func (r Repo) IsZero() bool { return r.owner == "" }

func (r Repo) String() string {
	if r.IsZero() {
		return ""
	}
	return r.owner + "/" + r.name
}

func checkOwnerName(owner string) error {
	if !ownerNameRE.MatchString(owner) {
		return fmt.Errorf("owner %q must be 1 to 100 letters, digits, '-' or '_', starting with a letter or digit", owner)
	}
	return nil
}

func checkPrincipalName(kind, name string) error {
	if !principalNameRE.MatchString(name) {
		return fmt.Errorf("%s name %q must be 1 to 64 lowercase letters, digits, '.', '-' or '_', starting with a letter or digit", kind, name)
	}
	return nil
}
