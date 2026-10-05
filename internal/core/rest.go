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
// hardRuleClasses recognizes their method and path families on its own, NewRESTTable rejects entries
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
// and "**" is any number of segments, none included. Every pattern starts with a literal segment,
// so the first segment of a path, which templates must spell out, decides which families can
// apply.
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
	// "branches/*/**/..." needs a branch name first: GET branches/{branch} for a branch called
	// "protection" is not the protection endpoint.
	{ClassAdmin, true, []string{"", "transfer", "forks", "topics/**", "branches/*/**/rename"}},
	{ClassAdmin, false, []string{
		"collaborators/**", "invitations/**", "hooks/**", "keys/**", "environments/**", "rulesets/**",
		"pages/**", "autolinks/**", "vulnerability-alerts/**", "automated-security-fixes/**",
		"private-vulnerability-reporting/**",
		"actions/permissions/**", "actions/runners/**", "actions/runner-groups/**", "actions/oidc/**",
		"actions/cache/**", "actions/caches/**",
		"actions/secrets/**", "actions/variables/**", "actions/organization-secrets/**",
		"actions/organization-variables/**", "dependabot/secrets/**", "codespaces/secrets/**",
		"branches/*/**/protection/**",
	}},
}

// hardRuleClasses returns every hard rule whose family method and path can reach, in the order of
// families. Paths outside /repos/{owner}/{repo} are all covered (unscoped), except GET /rate_limit
// and GET /meta. In a template, a {parameter} segment stands for any one segment, so a template is
// covered when some value of its parameters would be.
func hardRuleClasses(method, path string) []Class {
	rest, inRepo := strings.CutPrefix(path, repoPathPrefix)
	if !inRepo || rest != "" && !strings.HasPrefix(rest, "/") {
		if slices.Contains(globalRoutes, method+" "+path) {
			return nil
		}
		return []Class{ClassUnscoped}
	}
	var segs []string
	if rest != "" {
		segs = strings.Split(rest[1:], "/")
	}
	write := method != "GET"
	var classes []Class
	for _, f := range families {
		if f.writesOnly && !write || slices.Contains(classes, f.class) {
			continue
		}
		for _, p := range f.patterns {
			if matchSegments(splitPattern(p), segs) {
				classes = append(classes, f.class)
				break
			}
		}
	}
	return classes
}

func splitPattern(p string) []string {
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

// matchSegments reports whether segs match pattern, where "*" matches one segment and "**" any
// number of segments; a {parameter} in segs matches any one pattern segment. Patterns are the
// fixed families above, with at most two "**".
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
	return len(segs) > 0 && (pattern[0] == "*" || pattern[0] == segs[0] || isParam(segs[0])) &&
		matchSegments(pattern[1:], segs[1:])
}

func isParam(seg string) bool {
	return strings.HasPrefix(seg, "{")
}

// class returns the operation's class, unless a hard rule it can reach says otherwise: then the
// first such hard rule.
func (o RESTOperation) class() Class {
	hard := hardRuleClasses(o.Method, o.Path)
	if len(hard) == 0 || slices.Contains(hard, o.Class) {
		return o.Class
	}
	return hard[0]
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
			errs = append(errs, fmt.Errorf("operation %s is defined twice", Printable(op.Name)))
			continue
		}
		route := op.Method + " " + op.Path
		if other, dup := routes[route]; dup {
			errs = append(errs, fmt.Errorf("operations %s and %s both use %s", Printable(other), Printable(op.Name), Printable(route)))
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
	name := Printable(op.Name)
	if !operationNameRE.MatchString(op.Name) {
		return fmt.Errorf("operation %s: the name must be lowercase dotted words, e.g. pulls.create", name)
	}
	switch op.Method {
	case "GET", "POST", "PUT", "PATCH", "DELETE":
	default:
		return fmt.Errorf("operation %s: unknown method %s", name, Printable(op.Method))
	}
	if _, ok := classNames[op.Class]; !ok {
		return fmt.Errorf("operation %s: unknown class %d", name, op.Class)
	}
	if (op.Class == ClassRead || op.Class == ClassGlobal) && op.Method != "GET" {
		return fmt.Errorf("operation %s: only GET operations can be read or global, not %s", name, Printable(op.Method))
	}
	inRepo := op.Path == repoPathPrefix || strings.HasPrefix(op.Path, repoPathPrefix+"/")
	switch {
	case !pathTemplateRE.MatchString(op.Path):
		return fmt.Errorf("operation %s: path %s must be '/'-separated segments of lowercase letters, digits, '-' and '_', or whole-segment {parameters}", name, Printable(op.Path))
	case op.repoScoped() && !inRepo:
		return fmt.Errorf("operation %s: path %s must start with %s", name, Printable(op.Path), repoPathPrefix)
	case !op.repoScoped() && inRepo:
		return fmt.Errorf("operation %s: path %s is repository-scoped; use a repository class", name, Printable(op.Path))
	case op.Class == ClassGlobal && !slices.Contains(globalRoutes, op.Method+" "+op.Path):
		return fmt.Errorf("operation %s: only %s can be global", name, strings.Join(globalRoutes, " and "))
	case inRepo && op.Path != repoPathPrefix && isParam(strings.Split(op.Path, "/")[4]):
		return fmt.Errorf("operation %s: path %s must spell out the segment after %s", name, Printable(op.Path), repoPathPrefix)
	}
	if hard := hardRuleClasses(op.Method, op.Path); len(hard) > 0 && !slices.Contains(hard, op.Class) {
		names := make([]string, len(hard))
		for i, c := range hard {
			names[i] = c.String()
		}
		return fmt.Errorf("operation %s: %s %s can reach a hard rule; its class must be %s", name, Printable(op.Method), Printable(op.Path), strings.Join(names, " or "))
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
