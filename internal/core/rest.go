package core

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Class says what allows a REST operation: a preset, every user, or nothing (a hard rule).
// Each entry of the operation table has exactly one class. The hard rules do not depend on it:
// hardRuleClass recognizes their method and path families on its own, NewRESTTable rejects entries
// classified otherwise, and Decide denies them whatever the class says.
type Class int

const (
	// ClassRead operations are allowed by the read and pr presets. GET only.
	ClassRead Class = iota + 1
	// ClassPR operations are allowed by the pr preset.
	ClassPR
	// ClassGlobal operations are not repository-scoped and are allowed for every enabled user
	// (GET /rate_limit, GET /meta). GET only.
	ClassGlobal
	// The remaining classes are hard rules: always denied, whatever the grants say.

	// ClassCodeChange: contents and git data writes, branch merges and syncs. Every code change
	// goes through the push checks in one place.
	ClassCodeChange
	// ClassMerge: merging pull requests.
	ClassMerge
	// ClassAdmin: repository administration (settings, collaborators, hooks, keys, secrets, ...).
	ClassAdmin
	// ClassRelease: release writes. A release creates a tag, and tags cannot be pushed.
	ClassRelease
	// ClassCIResult: commit statuses, check runs and check suites, which an agent could forge.
	ClassCIResult
	// ClassTrigger: workflow dispatches and deployments, which run with the repository's secrets.
	ClassTrigger
	// ClassUnscoped: endpoints that are not repository-scoped (/user, /orgs, /search, ...).
	ClassUnscoped
)

var classNames = map[Class]string{
	ClassRead:       "read",
	ClassPR:         "pr",
	ClassGlobal:     "global",
	ClassCodeChange: "code change",
	ClassMerge:      "merge",
	ClassAdmin:      "admin",
	ClassRelease:    "release",
	ClassCIResult:   "ci result",
	ClassTrigger:    "trigger",
	ClassUnscoped:   "unscoped",
}

func (c Class) String() string {
	if name, ok := classNames[c]; ok {
		return name
	}
	return fmt.Sprintf("class %d", int(c))
}

// hardRules gives the reason of each hard-rule class: why, then what to do instead.
var hardRules = map[Class]string{
	ClassCodeChange: "code changes go through git push only; push to an allowed branch instead",
	ClassMerge:      "ghgw never merges pull requests; ask a person to merge",
	ClassAdmin:      "repository administration is not available through ghgw",
	ClassRelease:    "releases create tags, and tags cannot be pushed through ghgw; ask a person to release",
	ClassCIResult:   "CI results come from CI, not from agents",
	ClassTrigger:    "triggering workflows and deployments is not available through ghgw; push to a branch and let CI run",
	ClassUnscoped:   "only repository endpoints (repos/{owner}/{repo}/...), rate_limit and meta are available",
}

// allows reports whether preset p allows operations of class c. Presets are cumulative.
func (p Preset) allows(c Class) bool {
	switch p {
	case PresetRead:
		return c == ClassRead
	case PresetPR:
		return c == ClassRead || c == ClassPR
	}
	return false
}

// presetFor returns the smallest preset that allows class c, or PresetNone if none does.
func presetFor(c Class) Preset {
	switch c {
	case ClassRead:
		return PresetRead
	case ClassPR:
		return PresetPR
	}
	return PresetNone
}

// RESTOperation is one entry of the REST operation table: a method and path template classified
// under a name.
type RESTOperation struct {
	// Name identifies the operation in decisions and explain ("pulls.create").
	Name   string
	Method string
	// Path is the template relative to the API root, in canonical form: segments of lowercase
	// letters, digits, '-' and '_', or whole-segment {parameters}, e.g.
	// "/repos/{owner}/{repo}/pulls/{pull_number}". No escapes, dots or other delimiters, so the
	// hard-rule families and the classifier (M7) read a path the way GitHub does.
	// Repository-scoped operations start with "/repos/{owner}/{repo}"; the others do not.
	Path  string
	Class Class
}

const repoPathPrefix = "/repos/{owner}/{repo}"

// globalRoutes are the only operations outside a repository that are allowed (SPEC.md 5.3).
var globalRoutes = []string{"GET /rate_limit", "GET /meta"}

// A family is a set of repository paths (segments after /repos/{owner}/{repo}) that a hard rule
// covers, for writes (any method but GET) or for every method. In patterns, "*" is one segment
// and "**" is any number of segments, none included.
type family struct {
	class      Class
	writesOnly bool
	patterns   []string
}

// families are the hard-rule backstop: they do not trust the table's classification. The table
// remains the allow-list, and anything it does not list is denied; the families only make sure
// that a misclassified entry cannot allow what a hard rule forbids.
var families = []family{
	// Every code change goes through the push checks; these change branches without a push.
	{ClassCodeChange, true, []string{"contents/**", "git/**", "merges", "merge-upstream", "pulls/*/update-branch"}},
	{ClassMerge, true, []string{"pulls/*/merge"}},
	{ClassRelease, true, []string{"releases/**"}},
	{ClassCIResult, true, []string{"statuses/**", "check-runs/**", "check-suites/**"}},
	{ClassTrigger, true, []string{"dispatches", "actions/workflows/*/dispatches", "deployments/**"}},
	{ClassAdmin, true, []string{"", "transfer", "forks", "topics/**", "branches/**/rename"}},
	{ClassAdmin, false, []string{
		"collaborators/**", "invitations/**", "hooks/**", "keys/**", "environments/**", "rulesets/**",
		"pages/**", "autolinks/**", "vulnerability-alerts/**", "automated-security-fixes/**",
		"private-vulnerability-reporting/**",
		"actions/permissions/**", "actions/runners/**", "actions/runner-groups/**", "actions/oidc/**",
		"actions/cache/**", "actions/caches/**",
		"**/secrets/**", "**/variables/**", "**/organization-secrets/**", "**/organization-variables/**",
		"branches/**/protection/**",
	}},
}

// hardRuleClass returns the hard rule whose family covers method and path, if any. Paths outside
// /repos/{owner}/{repo} are all covered (unscoped), except GET /rate_limit and GET /meta.
func hardRuleClass(method, path string) (Class, bool) {
	rest, inRepo := strings.CutPrefix(path, repoPathPrefix)
	if !inRepo || rest != "" && !strings.HasPrefix(rest, "/") {
		if slices.Contains(globalRoutes, method+" "+path) {
			return 0, false
		}
		return ClassUnscoped, true
	}
	var segs []string
	if rest != "" {
		segs = strings.Split(rest[1:], "/")
	}
	write := method != "GET"
	for _, f := range families {
		if f.writesOnly && !write {
			continue
		}
		for _, p := range f.patterns {
			if matchSegments(splitPattern(p), segs) {
				return f.class, true
			}
		}
	}
	return 0, false
}

func splitPattern(p string) []string {
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

// matchSegments reports whether segs match pattern, where "*" matches one segment and "**" any
// number of segments. Patterns are the fixed families above, with at most two "**".
func matchSegments(pattern, segs []string) bool {
	if len(pattern) == 0 {
		return len(segs) == 0
	}
	if pattern[0] == "**" {
		for i := 0; i <= len(segs); i++ {
			if matchSegments(pattern[1:], segs[i:]) {
				return true
			}
		}
		return false
	}
	return len(segs) > 0 && (pattern[0] == "*" || pattern[0] == segs[0]) && matchSegments(pattern[1:], segs[1:])
}

// class returns the operation's class, overridden by the hard rule that covers it, if any.
func (o RESTOperation) class() Class {
	if hard, ok := hardRuleClass(o.Method, o.Path); ok {
		return hard
	}
	return o.Class
}

func (o RESTOperation) repoScoped() bool {
	return o.Class != ClassGlobal && o.Class != ClassUnscoped
}

// RESTTable is a validated set of REST operations, looked up by name.
type RESTTable struct {
	byName map[string]RESTOperation
}

var (
	operationNameRE = regexp.MustCompile(`^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)*$`)
	pathTemplateRE  = regexp.MustCompile(`^(/([a-z0-9_-]+|\{[a-z][a-z0-9_]*\}))+$`)
)

// NewRESTTable validates ops and builds a table. The error lists every problem.
func NewRESTTable(ops []RESTOperation) (*RESTTable, error) {
	t := &RESTTable{byName: make(map[string]RESTOperation, len(ops))}
	routes := make(map[string]string, len(ops))
	var errs []error
	for _, op := range ops {
		if err := checkOperation(op); err != nil {
			errs = append(errs, err)
			continue
		}
		if _, dup := t.byName[op.Name]; dup {
			errs = append(errs, fmt.Errorf("operation %s is defined twice", op.Name))
			continue
		}
		route := op.Method + " " + op.Path
		if other, dup := routes[route]; dup {
			errs = append(errs, fmt.Errorf("operations %s and %s both use %s", other, op.Name, route))
			continue
		}
		routes[route] = op.Name
		t.byName[op.Name] = op
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return t, nil
}

func checkOperation(op RESTOperation) error {
	if !operationNameRE.MatchString(op.Name) {
		return fmt.Errorf("operation %q: the name must be lowercase dotted words, e.g. pulls.create", op.Name)
	}
	switch op.Method {
	case "GET", "POST", "PUT", "PATCH", "DELETE":
	default:
		return fmt.Errorf("operation %s: unknown method %q", op.Name, op.Method)
	}
	if _, ok := classNames[op.Class]; !ok {
		return fmt.Errorf("operation %s: unknown class %d", op.Name, op.Class)
	}
	if (op.Class == ClassRead || op.Class == ClassGlobal) && op.Method != "GET" {
		return fmt.Errorf("operation %s: only GET operations can be read or global, not %s", op.Name, op.Method)
	}
	inRepo := op.Path == repoPathPrefix || strings.HasPrefix(op.Path, repoPathPrefix+"/")
	switch {
	case !pathTemplateRE.MatchString(op.Path):
		return fmt.Errorf("operation %s: path %q must be '/'-separated segments of lowercase letters, digits, '-' and '_', or whole-segment {parameters}", op.Name, printable(op.Path))
	case op.repoScoped() && !inRepo:
		return fmt.Errorf("operation %s: path %q must start with %s", op.Name, op.Path, repoPathPrefix)
	case !op.repoScoped() && inRepo:
		return fmt.Errorf("operation %s: path %q is repository-scoped; use a repository class", op.Name, op.Path)
	case op.Class == ClassGlobal && !slices.Contains(globalRoutes, op.Method+" "+op.Path):
		return fmt.Errorf("operation %s: only %s can be global", op.Name, strings.Join(globalRoutes, " and "))
	}
	if hard := op.class(); hard != op.Class {
		return fmt.Errorf("operation %s: %s %s falls under a hard rule; its class must be %s", op.Name, op.Method, op.Path, hard)
	}
	return nil
}

// lookup returns the operation called name. A nil table has no operations.
func (t *RESTTable) lookup(name string) (RESTOperation, bool) {
	if t == nil {
		return RESTOperation{}, false
	}
	op, ok := t.byName[name]
	return op, ok
}
