package core

import (
	"fmt"
	"net/url"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The limits of a REST path bound the work of classifying it, whatever the request: real paths
// (file paths in contents/{path} included) are far shorter.
const (
	MaxRESTPathLen      = 8 << 10
	MaxRESTPathSegments = 256
)

// RESTPath is the canonical form of a REST request's path, relative to the API root: decoded once
// and split into segments, none of them empty, "." or "..", and none holding '%', '\', a control
// character or invalid UTF-8. A request is decided on these segments and forwarded as them (String),
// so GitHub sees the segments ghgw classified.
type RESTPath struct {
	segs []string
}

// ParseRESTPath parses a path that was decoded once ("/repos/o/r/branches/agent/fix" for a request
// sent as ".../branches/agent%2Ffix"). "/" is the API root.
func ParseRESTPath(path string) (RESTPath, error) {
	if len(path) > MaxRESTPathLen {
		return RESTPath{}, fmt.Errorf("the API path is %d bytes, longer than the %d ghgw reads", len(path), MaxRESTPathLen)
	}
	rest, ok := strings.CutPrefix(path, "/")
	if !ok {
		return RESTPath{}, fmt.Errorf("the API path %s must start with /", Printable(path))
	}
	if rest == "" {
		return RESTPath{}, nil
	}
	segs := strings.Split(rest, "/")
	if len(segs) > MaxRESTPathSegments {
		return RESTPath{}, fmt.Errorf("the API path has %d segments, more than the %d ghgw reads", len(segs), MaxRESTPathSegments)
	}
	for _, s := range segs {
		var problem string
		switch {
		case s == "":
			problem = "an empty segment; remove the doubled or trailing /"
		case s == "." || s == "..":
			problem = "a . or .. segment; write the path without them"
		case strings.ContainsAny(s, `%\`):
			problem = "a % or \\ once decoded; ghgw decodes a path once, so escape each character once"
		case !utf8.ValidString(s) || strings.ContainsFunc(s, unicode.IsControl):
			problem = "a control character or invalid UTF-8"
		default:
			continue
		}
		return RESTPath{}, fmt.Errorf("the API path %s has %s", Printable(path), problem)
	}
	return RESTPath{segs: segs}, nil
}

// String returns the path to forward: each segment escaped again, so GitHub decodes the segments
// that were decided on.
func (p RESTPath) String() string {
	escaped := make([]string, len(p.segs))
	for i, s := range p.segs {
		escaped[i] = url.PathEscape(s)
	}
	return "/" + strings.Join(escaped, "/")
}

// display returns the decoded path, for reasons; render it with Printable.
func (p RESTPath) display() string {
	return "/" + strings.Join(p.segs, "/")
}

func (p RESTPath) inRepo() bool {
	return len(p.segs) >= 3 && p.segs[0] == "repos"
}

// Repo returns the repository of a /repos/{owner}/{repo} path, or the zero Repo for a path that is
// not repository-scoped. The names follow core's rules: a path that names an invalid repository is
// an error.
func (p RESTPath) Repo() (Repo, error) {
	if !p.inRepo() {
		return Repo{}, nil
	}
	return ParseRepo(p.segs[1] + "/" + p.segs[2])
}

// hardRules returns the hard rules that method and the path reach, as hardRuleClasses does for a
// template. Segments are compared in lowercase, so no spelling of a family path that GitHub might
// route the same way escapes it; a branch or file name that merely looks like one is denied too.
func (p RESTPath) hardRules(method string) []Class {
	if !p.inRepo() {
		if slices.Contains(globalRoutes, method+" "+p.display()) {
			return nil
		}
		return []Class{ClassUnscoped}
	}
	rest := make([]string, len(p.segs)-3)
	for i, s := range p.segs[3:] {
		rest[i] = strings.ToLower(s)
	}
	return familyClasses(method, rest)
}

// RESTRequest is a REST request as the gateway got it: its method and canonical path. Decide
// classifies it with the policy's operation table (Decision.Operation), and checks the hard-rule
// families on the path itself before the table, which also covers the longer values of a parameter
// that spans segments. The request's Repo must be the path's.
type RESTRequest struct {
	Method string
	Path   RESTPath
}

func (o RESTRequest) operation() string { return o.Method + " " + o.Path.display() }

// segKind is what a segment of a template matches. Lower kinds are more specific: when several
// templates match a request, the first segment where they differ decides, and the lower kind wins.
type segKind int

const (
	segLiteral segKind = iota
	// segInteger is a parameter GitHub types as an integer: ASCII digits only.
	segInteger
	// segParam is any other parameter: any one segment.
	segParam
	// segSpan is a parameter that matches one or more segments.
	segSpan
)

// integerParams are the parameters GitHub types as integers. Without them, pulls/{pull_number}
// would also match pulls/comments, a repository-wide list the table leaves out.
var integerParams = []string{"pull_number", "issue_number", "review_id", "comment_id", "run_id", "job_id"}

// spanningRoutes are the routes whose last parameter spans segments, and whether it may also match
// none (bare contents is the root directory). A parameter may span only when it ends a read
// template and every GET route GitHub has below it is in a hard-rule family, so that a longer value
// cannot name an operation the table leaves out: none below contents/{path}, only branch protection
// below branches/{branch}. commits/{ref} fails that test (commits/{ref}/comments), so {ref} is one
// segment. Only GitHub's description can tell, so each route is listed by hand.
var spanningRoutes = map[string]bool{
	"GET /repos/{owner}/{repo}/contents/{path}":   true,
	"GET /repos/{owner}/{repo}/branches/{branch}": false,
}

type routeSeg struct {
	kind    segKind
	literal string
	// empty allows a spanning parameter to match no segment.
	empty bool
}

// route is an operation with its template compiled for matching.
type route struct {
	op   RESTOperation
	segs []routeSeg
}

func newRoute(op RESTOperation) route {
	parts := strings.Split(op.Path[1:], "/")
	rt := route{op: op, segs: make([]routeSeg, len(parts))}
	empty, spans := spanningRoutes[op.Method+" "+op.Path]
	for i, p := range parts {
		name, isParam := strings.CutPrefix(p, "{")
		name = strings.TrimSuffix(name, "}")
		switch {
		case !isParam:
			rt.segs[i] = routeSeg{kind: segLiteral, literal: p}
		case slices.Contains(integerParams, name):
			rt.segs[i] = routeSeg{kind: segInteger}
		case spans && i == len(parts)-1 && op.Class == ClassRead:
			rt.segs[i] = routeSeg{kind: segSpan, empty: empty}
		default:
			rt.segs[i] = routeSeg{kind: segParam}
		}
	}
	return rt
}

// shape is the route with its parameters reduced to their kind: two routes of one shape would
// match the same requests.
func (rt route) shape() string {
	var b strings.Builder
	b.WriteString(rt.op.Method + " ")
	for _, s := range rt.segs {
		b.WriteByte('/')
		switch s.kind {
		case segLiteral:
			b.WriteString(s.literal)
		case segInteger:
			b.WriteString("{integer}")
		case segParam:
			b.WriteString("{}")
		case segSpan:
			fmt.Fprintf(&b, "{span empty=%v}", s.empty)
		}
	}
	return b.String()
}

// match reports whether the route matches a request with method and segments, and the kind of
// template segment each request segment matched, to rank the routes that match. A spanning
// parameter that matches no segment counts as one more, so the template that ends with the request
// beats it.
func (rt route) match(method string, segs []string) ([]segKind, bool) {
	if method != rt.op.Method {
		return nil, false
	}
	kinds := make([]segKind, 0, len(segs)+1)
	for i, ts := range rt.segs {
		if ts.kind == segSpan {
			n := len(segs) - i
			if n < 0 || n == 0 && !ts.empty {
				return nil, false
			}
			for range max(n, 1) {
				kinds = append(kinds, segSpan)
			}
			return kinds, true
		}
		if i >= len(segs) {
			return nil, false
		}
		switch ts.kind {
		case segLiteral:
			if segs[i] != ts.literal {
				return nil, false
			}
		case segInteger:
			if strings.TrimLeft(segs[i], "0123456789") != "" {
				return nil, false
			}
		}
		kinds = append(kinds, ts.kind)
	}
	return kinds, len(rt.segs) == len(segs)
}

// match returns the operation a request with method and path is, if any. Literals are compared as
// they are: the table is the allow-list, so another spelling is an unknown operation.
func (t *RESTTable) match(method string, path RESTPath) (RESTOperation, bool) {
	if t == nil {
		return RESTOperation{}, false
	}
	var best []segKind
	var found *route
	for i, rt := range t.routes {
		if kinds, ok := rt.match(method, path.segs); ok && (found == nil || slices.Compare(kinds, best) < 0) {
			best, found = kinds, &t.routes[i]
		}
	}
	if found == nil {
		return RESTOperation{}, false
	}
	return found.op, true
}

// near returns the guidance for a request that matches no operation: the routes of the table under
// the same resource (the segment after the repository), or all of them.
func (t *RESTTable) near(path RESTPath) string {
	var near, all []string
	if t != nil {
		for _, rt := range t.routes {
			s := rt.op.Method + " " + rt.op.Path
			all = append(all, s)
			if len(path.segs) > 3 && len(rt.segs) > 3 && rt.segs[3].literal == path.segs[3] {
				near = append(near, s)
			}
		}
	}
	if len(near) == 0 {
		near = all
	}
	return "; ghgw forwards: " + boundedList(near)
}

// decideRESTRequest decides a request on its concrete path: the repository, the hard-rule families,
// then the table and the grants.
func (p *Policy) decideRESTRequest(r Request, call RESTRequest, grants []*Grant) Decision {
	name := Printable(call.operation())
	if repo, err := call.Path.Repo(); err != nil || repo != r.Repo {
		return deny(r, denialf("%s is decided on another repository than its path names", name))
	}
	hard := call.Path.hardRules(call.Method)
	if r.Repo.IsZero() && len(hard) > 0 {
		return deny(r, denialf("%s is not allowed: %s", name, unscopedReason(call.Path)))
	}
	if !r.Repo.IsZero() {
		if _, why := matchRepo(r, grants); why != nil {
			return deny(r, why)
		}
		if len(hard) > 0 {
			return deny(r, denialf("%s is not allowed: %s", name, hardRules[hard[0]]))
		}
	}
	op, ok := p.rest.match(call.Method, call.Path)
	if !ok {
		return deny(r, &denial{reason: name + " is not an API operation ghgw forwards", guidance: p.rest.near(call.Path)})
	}
	d := p.decideOperation(r, op, grants)
	d.Operation = op.Name
	return d
}

// unscopedReason says why a path outside the repositories is denied. GitHub answers for a renamed
// or transferred repository with a redirect to repositories/{id}/..., which names no repository
// ghgw could decide on.
func unscopedReason(path RESTPath) string {
	if len(path.segs) > 0 && path.segs[0] == "repositories" {
		return "ghgw decides by repository name, and GitHub uses repositories/ID paths for a repository that was renamed or transferred; use its new name (repos/OWNER/NAME/...)"
	}
	return hardRules[ClassUnscoped]
}
