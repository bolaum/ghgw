package gateway

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net/http"
	"net/http/httputil"
	"strings"

	"github.com/bolaum/ghgw/internal/core"
	"github.com/bolaum/ghgw/internal/store"
)

// The git services of smart HTTP.
const (
	uploadPack  = "git-upload-pack"
	receivePack = "git-receive-pack"
)

// gitRequest is a git smart HTTP request, as parsed once: everything forwarded is rebuilt from it.
type gitRequest struct {
	repo    core.Repo
	service string
	// advertisement is the ref advertisement (GET info/refs); the service call is a POST.
	advertisement bool
}

// suffix returns the path below the repository, as GitHub serves it.
func (q gitRequest) suffix() string {
	if q.advertisement {
		return "info/refs"
	}
	return q.service
}

// requestError is why a request cannot be parsed: an HTTP status and a message for fail.
type requestError struct {
	status int
	msg    string
}

// parseGitRequest parses the method, path and query of a git smart HTTP request:
// GET /<owner>/<repo>[.git]/info/refs?service=<service> and POST /<owner>/<repo>[.git]/<service>.
// The owner and repository follow core's rules, which leave nothing to escape, so a path that was
// sent escaped is rejected rather than decoded into another one.
func parseGitRequest(r *http.Request) (gitRequest, *requestError) {
	notGit := &requestError{http.StatusNotFound, "not a git repository URL; ghgw serves git at /OWNER/REPO.git"}
	if r.URL.RawPath != "" {
		return gitRequest{}, notGit
	}
	segs := strings.Split(r.URL.Path, "/")
	var q gitRequest
	switch {
	case len(segs) == 5 && segs[0] == "" && segs[3] == "info" && segs[4] == "refs":
		q.advertisement = true
		service, ok := strings.CutPrefix(r.URL.RawQuery, "service=")
		if !ok || (service != uploadPack && service != receivePack) {
			return gitRequest{}, &requestError{http.StatusBadRequest, "ghgw serves git's smart HTTP protocol only; use git 1.6.6 or later"}
		}
		q.service = service
		if r.Method != http.MethodGet {
			return gitRequest{}, &requestError{http.StatusMethodNotAllowed, "the ref advertisement is fetched with GET"}
		}
	case len(segs) == 4 && segs[0] == "" && (segs[3] == uploadPack || segs[3] == receivePack):
		q.service = segs[3]
		if r.Method != http.MethodPost {
			return gitRequest{}, &requestError{http.StatusMethodNotAllowed, "git services are called with POST"}
		}
		if r.URL.RawQuery != "" {
			return gitRequest{}, &requestError{http.StatusBadRequest, "git services take no query string"}
		}
	default:
		return gitRequest{}, notGit
	}
	// The .git suffix is optional, as on GitHub; core rejects repository names that still end in
	// it, so /o/x.git always means repository x.
	name := segs[2]
	if strings.HasSuffix(strings.ToLower(name), ".git") {
		name = name[:len(name)-len(".git")]
	}
	repo, err := core.ParseRepo(segs[1] + "/" + name)
	if err != nil {
		return gitRequest{}, &requestError{http.StatusNotFound, err.Error()}
	}
	q.repo = repo
	return q, nil
}

// serveGit serves a git smart HTTP request: parse, authenticate, decide, then forward.
func (g *Gateway) serveGit(w http.ResponseWriter, r *http.Request) {
	q, perr := parseGitRequest(r)
	if perr != nil {
		fail(w, perr.status, "%s", perr.msg)
		return
	}
	snap, err := g.policy.current(r.Context())
	if err != nil {
		// The error is in the log; it may name paths and policy details the agent has no use for.
		fail(w, http.StatusServiceUnavailable, "the gateway has no valid policy, so every request is denied; ask the admin to fix the policy file (the gateway's log says what is wrong)")
		return
	}
	user, ok := authenticate(w, r, snap)
	if !ok {
		return
	}
	if q.service == receivePack {
		fail(w, http.StatusNotImplemented, "this gateway does not accept pushes yet; ask the admin")
		return
	}
	d := snap.policy.Decide(core.Request{User: user, Repo: q.repo, Op: core.Fetch{}})
	if !d.Allowed {
		fail(w, http.StatusForbidden, "%s", d.Reason)
		return
	}
	token, err := g.store.Credential(r.Context(), q.repo.Owner())
	switch {
	case errors.Is(err, store.ErrNotFound):
		// Removed since the policy was read.
		fail(w, http.StatusForbidden, "ghgw has no credential for owner %s; ask the admin to add one", core.Printable(q.repo.Owner()))
		return
	case err != nil:
		g.log.Error("cannot read a credential", "owner", q.repo.Owner(), "error", err)
		fail(w, http.StatusInternalServerError, "the gateway cannot use the credential of owner %s; ask the admin to check the gateway's log", core.Printable(q.repo.Owner()))
		return
	}
	g.forward(w, r, q, user, token)
}

// authenticate returns the user whose ghgw key r carries, or answers 401 (SPEC.md section 5.1).
func authenticate(w http.ResponseWriter, r *http.Request, snap *snapshot) (string, bool) {
	key, given := keyFrom(r.Header)
	if !given {
		// Basic: git asks its credential helper (ghgw credential) only after this challenge.
		w.Header().Set("WWW-Authenticate", `Basic realm="ghgw"`)
		fail(w, http.StatusUnauthorized, "this gateway needs a ghgw key; ask the admin for one and run ghgw setup with it")
		return "", false
	}
	if hash, ok := store.HashUserKey(key); ok {
		if user, ok := snap.file.UserByKeyHash(hash); ok {
			return user, true
		}
	}
	w.Header().Set("WWW-Authenticate", `Basic realm="ghgw"`)
	fail(w, http.StatusUnauthorized, "unknown ghgw key; run ghgw setup again with the key the admin gave you, or ask the admin for a new one")
	return "", false
}

// keyFrom returns the ghgw key in h: the password of Basic authentication (git; the username is
// ignored), or the credentials of the token and Bearer schemes (gh). given is false when there is
// no Authorization header; a header in any other form gives an empty key, which is unknown.
func keyFrom(h http.Header) (key store.Secret, given bool) {
	values := h.Values("Authorization")
	switch len(values) {
	case 0:
		return store.Secret{}, false
	case 1:
	default:
		return store.Secret{}, true
	}
	scheme, credentials, _ := strings.Cut(values[0], " ")
	switch {
	case strings.EqualFold(scheme, "Basic"):
		r := http.Request{Header: http.Header{"Authorization": values}}
		if _, password, ok := r.BasicAuth(); ok {
			return store.NewSecret(password), true
		}
	case strings.EqualFold(scheme, "token"), strings.EqualFold(scheme, "Bearer"):
		return store.NewSecret(strings.TrimSpace(credentials)), true
	}
	return store.Secret{}, true
}

// Only these headers pass between the client and GitHub, in each direction. Everything else stays:
// the client's Authorization holds its ghgw key, and GitHub's cookies and challenges are not the
// client's business.
var (
	requestHeaders  = []string{"Accept", "Accept-Encoding", "Content-Encoding", "Content-Type", "Git-Protocol", "User-Agent"}
	responseHeaders = []string{"Cache-Control", "Content-Encoding", "Content-Length", "Content-Type", "Expires", "Pragma"}
)

func copyHeaders(dst, src http.Header, names []string) {
	for _, name := range names {
		if v := src.Values(name); len(v) > 0 {
			dst[name] = append([]string(nil), v...)
		}
	}
}

// forward sends the request to GitHub with the owner's credential and streams the answer back.
// The upstream URL is built from the parsed request only.
func (g *Gateway) forward(w http.ResponseWriter, r *http.Request, q gitRequest, user string, token store.Secret) {
	target := *g.gitURL
	target.Path = "/" + q.repo.String() + ".git/" + q.suffix()
	if q.advertisement {
		target.RawQuery = "service=" + q.service
	} else {
		r.Body = http.MaxBytesReader(w, r.Body, g.limits.uploadPackBody)
	}
	log := g.log.With("user", user, "repo", q.repo.String(), "service", q.service)
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL = &target
			pr.Out.Host = ""
			pr.Out.Header = make(http.Header)
			copyHeaders(pr.Out.Header, pr.In.Header, requestHeaders)
			pr.Out.SetBasicAuth("x-access-token", token.Reveal())
		},
		Transport: g.transport,
		// Flush every write: git shows the progress GitHub sends while it packs.
		FlushInterval: -1,
		ModifyResponse: func(resp *http.Response) error {
			if err := checkUpstream(resp, q); err != nil {
				return err
			}
			h := make(http.Header)
			copyHeaders(h, resp.Header, responseHeaders)
			resp.Header = h
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			upstreamFailed(w, r, q, log, err)
		},
	}
	proxy.ServeHTTP(w, r)
}

// upstreamError is an answer from GitHub that is not passed on to the client.
type upstreamError struct {
	status      int
	contentType string
}

func (e *upstreamError) Error() string {
	if e.contentType != "" {
		return fmt.Sprintf("upstream answered %d with content type %s", e.status, core.Printable(e.contentType))
	}
	return fmt.Sprintf("upstream answered %d", e.status)
}

// checkUpstream accepts only a successful git answer. Anything else is the upstream's business
// (a 401 for the owner's credential, a redirect elsewhere) and gets the gateway's own answer: a 401
// passed on would make git drop the ghgw key, and a redirect would send the client elsewhere.
func checkUpstream(resp *http.Response, q gitRequest) error {
	if resp.StatusCode != http.StatusOK {
		return &upstreamError{status: resp.StatusCode}
	}
	want := "application/x-" + q.service + "-result"
	if q.advertisement {
		want = "application/x-" + q.service + "-advertisement"
	}
	ct := resp.Header.Get("Content-Type")
	if mt, _, err := mime.ParseMediaType(ct); err != nil || mt != want {
		return &upstreamError{status: resp.StatusCode, contentType: ct}
	}
	return nil
}

// upstreamFailed answers a request GitHub did not serve, with what the agent can do about it.
func upstreamFailed(w http.ResponseWriter, r *http.Request, q gitRequest, log *slog.Logger, err error) {
	repo := core.Printable(q.repo.String())
	owner := core.Printable(q.repo.Owner())
	var ue *upstreamError
	var mbe *http.MaxBytesError
	switch {
	case r.Context().Err() != nil && !errors.Is(r.Context().Err(), context.DeadlineExceeded):
		// The client went away; nobody reads an answer.
		return
	case errors.As(err, &mbe):
		fail(w, http.StatusRequestEntityTooLarge, "the request body is larger than the %d bytes ghgw forwards", mbe.Limit)
	case errors.As(err, &ue) && ue.contentType != "":
		log.Warn("upstream answered an unexpected content type", "error", err)
		fail(w, http.StatusBadGateway, "GitHub did not answer %s with git data; try again later", repo)
	case errors.As(err, &ue) && (ue.status == http.StatusUnauthorized || ue.status == http.StatusForbidden):
		log.Warn("upstream refused the owner's credential", "error", err)
		fail(w, http.StatusBadGateway, "GitHub refused the credential of owner %s for %s (%d %s); ask the admin to check that it is valid (ghgw owner list) and can read %s",
			owner, repo, ue.status, http.StatusText(ue.status), repo)
	case errors.As(err, &ue) && ue.status == http.StatusNotFound:
		fail(w, http.StatusNotFound, "GitHub has no repository %s that the credential of owner %s can read; check the name, or ask the admin to give the credential access to it",
			repo, owner)
	case errors.As(err, &ue) && ue.status >= 300 && ue.status < 400:
		log.Warn("upstream redirected", "error", err)
		fail(w, http.StatusBadGateway, "GitHub redirected the request for %s, and ghgw does not follow redirects; if the repository was renamed or transferred, use its new name", repo)
	case errors.As(err, &ue):
		log.Warn("upstream failed", "error", err)
		fail(w, http.StatusBadGateway, "GitHub answered %d %s for %s; try again later", ue.status, http.StatusText(ue.status), repo)
	case isTimeout(err):
		log.Warn("upstream timed out", "error", err)
		fail(w, http.StatusGatewayTimeout, "GitHub did not answer in time for %s; try again later", repo)
	default:
		log.Warn("cannot reach upstream", "error", err)
		fail(w, http.StatusBadGateway, "cannot reach GitHub for %s; try again later", repo)
	}
}
