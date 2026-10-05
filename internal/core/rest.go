package core

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Class says what allows a REST operation: a preset, every user, or nothing (a hard rule).
// Each entry of the operation table has exactly one class, so a hard-rule operation cannot be put
// in a preset by mistake.
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

	// ClassCodeChange: contents and git data writes. Every code change goes through the push
	// checks in one place.
	ClassCodeChange
	// ClassMerge: merging pull requests.
	ClassMerge
	// ClassAdmin: repository administration (settings, collaborators, hooks, keys, secrets, ...).
	ClassAdmin
	// ClassUnscoped: endpoints that are not repository-scoped (/user, /orgs, /search, ...).
	ClassUnscoped
)

// hardRules gives the reason of each hard-rule class: why, then what to do instead.
var hardRules = map[Class]string{
	ClassCodeChange: "code changes go through git push only; push to an allowed branch instead",
	ClassMerge:      "ghgw never merges pull requests; ask a person to merge",
	ClassAdmin:      "repository administration is not available through ghgw",
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
	// Path is the template relative to the API root, with {parameters}:
	// "/repos/{owner}/{repo}/pulls". Repository-scoped operations start with
	// "/repos/{owner}/{repo}"; the others do not.
	Path  string
	Class Class
}

func (o RESTOperation) repoScoped() bool {
	return o.Class != ClassGlobal && o.Class != ClassUnscoped
}

// RESTTable is a validated set of REST operations, looked up by name.
type RESTTable struct {
	byName map[string]RESTOperation
}

var operationNameRE = regexp.MustCompile(`^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)*$`)

const repoPathPrefix = "/repos/{owner}/{repo}"

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
	if op.Class < ClassRead || op.Class > ClassUnscoped {
		return fmt.Errorf("operation %s: unknown class %d", op.Name, op.Class)
	}
	if (op.Class == ClassRead || op.Class == ClassGlobal) && op.Method != "GET" {
		return fmt.Errorf("operation %s: only GET operations can be read or global, not %s", op.Name, op.Method)
	}
	inRepo := op.Path == repoPathPrefix || strings.HasPrefix(op.Path, repoPathPrefix+"/")
	switch {
	case !strings.HasPrefix(op.Path, "/"):
		return fmt.Errorf("operation %s: path %q must start with '/'", op.Name, op.Path)
	case op.repoScoped() && !inRepo:
		return fmt.Errorf("operation %s: path %q must start with %s", op.Name, op.Path, repoPathPrefix)
	case !op.repoScoped() && inRepo:
		return fmt.Errorf("operation %s: path %q is repository-scoped; use a repository class", op.Name, op.Path)
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
