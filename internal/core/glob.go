package core

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// RepoGlob is a repository pattern of a grant: "owner/name".
//
//   - The owner is literal: no wildcards, so a grant never reaches an owner the admin did not name,
//     including owners whose credentials are added later.
//   - The name may contain '*', which matches any run of characters, empty included ("bolaum/*",
//     "acme/agent-*"). "**" is rejected: names have no '/', so it would only mean '*'.
//   - Both parts match case-insensitively, like GitHub.
//   - The name cannot end in ".git" (see ParseRepo).
//
// The zero RepoGlob matches nothing.
type RepoGlob struct {
	text  string
	owner string
	name  *regexp.Regexp
}

// ParseRepoGlob parses a repository pattern.
func ParseRepoGlob(s string) (RepoGlob, error) {
	owner, name, ok := strings.Cut(s, "/")
	if !ok {
		return RepoGlob{}, fmt.Errorf("repository pattern %q: want owner/name, e.g. bolaum/* or acme/app", s)
	}
	if strings.Contains(owner, "*") {
		return RepoGlob{}, fmt.Errorf("repository pattern %q: the owner cannot contain '*'; add one pattern per owner", s)
	}
	if err := checkOwnerName(owner); err != nil {
		return RepoGlob{}, fmt.Errorf("repository pattern %q: %w", s, err)
	}
	if strings.Contains(name, "**") {
		return RepoGlob{}, fmt.Errorf("repository pattern %q: use '*' in the name, not '**'", s)
	}
	literal := strings.ReplaceAll(name, "*", "")
	if name == "" || name == "." || name == ".." || literal != "" && !repoNameRE.MatchString(literal) {
		return RepoGlob{}, fmt.Errorf("repository pattern %q: name must be letters, digits, '.', '-', '_' or '*'", s)
	}
	if hasGitSuffix(name) {
		return RepoGlob{}, fmt.Errorf("repository pattern %q: write the name without the .git suffix", s)
	}
	return RepoGlob{text: s, owner: owner, name: compileGlob(name, "(?i)", ".*")}, nil
}

// Match reports whether r matches the pattern.
func (g RepoGlob) Match(r Repo) bool {
	return g.name != nil && strings.EqualFold(g.owner, r.owner) && g.name.MatchString(r.name)
}

func (g RepoGlob) String() string { return g.text }

// BranchGlob is a push pattern of a grant, matched against branch names without "refs/heads/".
// It supports a subset of GitHub's branch filter patterns, with the same meaning:
//
//   - '*' matches any run of characters except '/': "agent/*" matches "agent/x", not "agent/x/y".
//   - "**" matches any run of characters, '/' included: "agent/**" matches "agent/x" and
//     "agent/x/y" (but not "agent", which is a different branch).
//   - Everything else is literal and case-sensitive, like git refs.
//
// GitHub's other special characters ('?', '+', '[', a leading '!') are rejected rather than taken
// literally, so a pattern copied from GitHub never means something else here. A pattern must admit
// a valid branch name: with each run of stars replaced by one letter, it must pass git
// check-ref-format. "a.*.b" and "agent/**" pass; "*.lock" and ".*" never match a valid branch and
// are rejected instead of silently allowing nothing. Requested refs are validated on their own.
// The zero BranchGlob matches nothing.
type BranchGlob struct {
	text string
	re   *regexp.Regexp
}

// ParseBranchGlob parses a branch pattern.
func ParseBranchGlob(s string) (BranchGlob, error) {
	if s == "" {
		return BranchGlob{}, errors.New("branch pattern is empty")
	}
	if strings.HasPrefix(s, "refs/") {
		return BranchGlob{}, fmt.Errorf("branch pattern %q: write the branch name without refs/heads/", s)
	}
	if strings.Contains(s, "***") {
		return BranchGlob{}, fmt.Errorf("branch pattern %q: use '*' or '**', not three stars", s)
	}
	if strings.Contains(s, "+") || strings.HasPrefix(s, "!") {
		return BranchGlob{}, fmt.Errorf("branch pattern %q: only literals, '*' and '**' are supported", s)
	}
	if err := checkRefName("refs/heads/" + starsRE.ReplaceAllString(s, "x")); err != nil {
		return BranchGlob{}, fmt.Errorf("branch pattern %q: %w", s, err)
	}
	return BranchGlob{text: s, re: compileGlob(s, "", "[^/]*")}, nil
}

// Match reports whether branch (without "refs/heads/") matches the pattern.
func (g BranchGlob) Match(branch string) bool {
	return g.re != nil && g.re.MatchString(branch)
}

func (g BranchGlob) String() string { return g.text }

var starsRE = regexp.MustCompile(`\*+`)

// compileGlob turns a glob into an anchored regexp: "**" matches anything, '*' matches star.
// RE2 matches in linear time, so no pattern can make a decision slow.
func compileGlob(glob, flags, star string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString(flags + "^")
	for i, part := range strings.Split(glob, "**") {
		if i > 0 {
			b.WriteString(".*")
		}
		for j, lit := range strings.Split(part, "*") {
			if j > 0 {
				b.WriteString(star)
			}
			b.WriteString(regexp.QuoteMeta(lit))
		}
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String())
}

// checkRefName applies the rules of git check-ref-format to a full ref name, so that two
// spellings of one ref (and refs GitHub would interpret differently) never reach a decision.
func checkRefName(ref string) error {
	switch {
	case !utf8.ValidString(ref):
		return errors.New("not valid UTF-8")
	case strings.HasSuffix(ref, "/") || strings.Contains(ref, "//"):
		return errors.New("cannot end with '/' or contain \"//\"")
	case strings.HasSuffix(ref, "."):
		return errors.New("cannot end with '.'")
	case strings.Contains(ref, ".."):
		return errors.New(`cannot contain ".."`)
	case strings.Contains(ref, "@{"):
		return errors.New(`cannot contain "@{"`)
	}
	for _, c := range ref {
		if c < 0x20 || c == 0x7f || strings.ContainsRune(" ~^:?*[\\", c) {
			return fmt.Errorf("cannot contain %q", c)
		}
	}
	for comp := range strings.SplitSeq(ref, "/") {
		if strings.HasPrefix(comp, ".") || strings.HasSuffix(comp, ".lock") {
			return errors.New(`no part between slashes can start with '.' or end with ".lock"`)
		}
	}
	return nil
}
