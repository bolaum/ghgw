package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net"
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
		// Only the service call's body is forwarded, and bounded.
		if r.ContentLength != 0 {
			return gitRequest{}, &requestError{http.StatusBadRequest, "the ref advertisement is fetched without a body"}
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
	snap, user, ok := g.authenticate(w, r, fail)
	if !ok {
		return
	}
	var op core.Operation = core.Fetch{}
	if q.service == receivePack {
		op = core.PushAccess{}
	}
	d := snap.policy.Decide(core.Request{User: user, Repo: q.repo, Op: op})
	if !d.Allowed {
		fail(w, http.StatusForbidden, "%s", d.Reason)
		return
	}
	if q.service == receivePack {
		fail(w, http.StatusNotImplemented, "this gateway does not accept pushes yet; ask the admin")
		return
	}
	token, ok := g.credential(w, r, q.repo, fail)
	if !ok {
		return
	}
	g.forward(w, r, q, user, token)
}

// authenticate returns the policy in force and the user whose ghgw key r carries, or answers 503
// (no policy) or 401 (SPEC.md section 5.1).
func (g *Gateway) authenticate(w http.ResponseWriter, r *http.Request, answer answerFunc) (*snapshot, string, bool) {
	snap, err := g.policy.current(r.Context())
	// The errors are in the log; they may name paths and policy details the agent has no use for.
	switch {
	case errors.Is(err, errStore):
		answer(w, http.StatusServiceUnavailable, "the gateway cannot read its store, so every request is denied; try again later, or ask the admin to check the gateway's log")
		return nil, "", false
	case err != nil:
		answer(w, http.StatusServiceUnavailable, "the gateway has no valid policy, so every request is denied; ask the admin to fix the policy file (the gateway's log says what is wrong)")
		return nil, "", false
	}
	key, given := keyFrom(r.Header)
	if !given {
		// Basic: git asks its credential helper (ghgw credential) only after this challenge.
		w.Header().Set("WWW-Authenticate", `Basic realm="ghgw"`)
		answer(w, http.StatusUnauthorized, "this gateway needs a ghgw key; ask the admin for one and run ghgw setup with it")
		return nil, "", false
	}
	if hash, ok := store.HashUserKey(key); ok {
		if user, ok := snap.file.UserByKeyHash(hash); ok {
			return snap, user, true
		}
	}
	w.Header().Set("WWW-Authenticate", `Basic realm="ghgw"`)
	answer(w, http.StatusUnauthorized, "unknown ghgw key; run ghgw setup again with the key the admin gave you, or ask the admin for a new one")
	return nil, "", false
}

// credential returns the credential of the owner of repo, or answers why there is none.
func (g *Gateway) credential(w http.ResponseWriter, r *http.Request, repo core.Repo, answer answerFunc) (store.Secret, bool) {
	token, err := g.store.Credential(r.Context(), repo.Owner())
	switch {
	case errors.Is(err, store.ErrNotFound):
		// Removed since the policy was read.
		answer(w, http.StatusForbidden, "ghgw has no credential for owner %s; ask the admin to add one", core.Printable(repo.Owner()))
		return store.Secret{}, false
	case err != nil:
		g.log.Error("cannot read a credential", "owner", repo.Owner(), "error", err)
		answer(w, http.StatusInternalServerError, "the gateway cannot use the credential of owner %s; ask the admin to check the gateway's log", core.Printable(repo.Owner()))
		return store.Secret{}, false
	}
	return token, true
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
		if r.ContentLength > g.limits.uploadPackBody {
			bodyTooLarge(w, g.limits.uploadPackBody)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, g.limits.uploadPackBody)
	}
	setDeadline(w, g.limits.request)
	ctx, cancel := context.WithTimeout(r.Context(), g.limits.request)
	defer cancel()
	r = r.WithContext(ctx)
	log := g.log.With("user", user, "repo", q.repo.String(), "service", q.service)
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL = &target
			pr.Out.Host = ""
			pr.Out.Header = make(http.Header)
			copyHeaders(pr.Out.Header, pr.In.Header, requestHeaders)
			pr.Out.Trailer = nil
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
			// Not announced; finalWriter drops them when they arrive.
			resp.Trailer = nil
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			upstreamFailed(w, r, q, log, err)
		},
		ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	proxy.ServeHTTP(&finalWriter{ResponseWriter: w}, r)
}

// finalWriter passes on the final answer only. ReverseProxy writes the upstream's 1xx answers with
// their headers and copies its trailers after the body, both outside ModifyResponse: 1xx answers
// are dropped, and headers set once the status is written (trailers) are discarded.
type finalWriter struct {
	http.ResponseWriter
	// after replaces the header once the status is written.
	after http.Header
}

func (f *finalWriter) Header() http.Header {
	if f.after != nil {
		return f.after
	}
	return f.ResponseWriter.Header()
}

func (f *finalWriter) WriteHeader(status int) {
	if status < 200 || f.after != nil {
		return
	}
	f.after = make(http.Header)
	f.ResponseWriter.WriteHeader(status)
}

func (f *finalWriter) Write(b []byte) (int, error) {
	f.WriteHeader(http.StatusOK)
	return f.ResponseWriter.Write(b)
}

// Unwrap lets ReverseProxy flush the underlying writer.
func (f *finalWriter) Unwrap() http.ResponseWriter { return f.ResponseWriter }

func bodyTooLarge(w http.ResponseWriter, limit int64) {
	fail(w, http.StatusRequestEntityTooLarge, "the request body is larger than the %d bytes ghgw forwards; fetch fewer refs at a time (git fetch origin BRANCH)", limit)
}

// upstreamError is an answer from GitHub that is not passed on to the client. It holds nothing
// GitHub wrote, so it can be logged.
type upstreamError struct {
	status int
	// notGit is a 200 without git's content type.
	notGit bool
}

func (e *upstreamError) Error() string {
	if e.notGit {
		return fmt.Sprintf("upstream answered %d without git's content type", e.status)
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
	if mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err != nil || mt != want {
		return &upstreamError{status: resp.StatusCode, notGit: true}
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
		bodyTooLarge(w, mbe.Limit)
	case errors.As(err, &ue) && ue.notGit:
		log.Warn("upstream failed", "error", ue.Error())
		fail(w, http.StatusBadGateway, "GitHub did not answer %s with git data; try again later", repo)
	case errors.As(err, &ue) && (ue.status == http.StatusUnauthorized || ue.status == http.StatusForbidden):
		log.Warn("upstream refused the owner's credential", "error", ue.Error())
		fail(w, http.StatusBadGateway, "GitHub refused the credential of owner %s for %s (%d %s); ask the admin to check that it is valid (ghgw owner list) and can read %s",
			owner, repo, ue.status, http.StatusText(ue.status), repo)
	case errors.As(err, &ue) && ue.status == http.StatusNotFound:
		fail(w, http.StatusNotFound, "GitHub has no repository %s that the credential of owner %s can read; check the name, or ask the admin to give the credential access to it",
			repo, owner)
	case errors.As(err, &ue) && ue.status >= 300 && ue.status < 400:
		log.Warn("upstream redirected", "error", ue.Error())
		fail(w, http.StatusBadGateway, "GitHub redirected the request for %s, and ghgw does not follow redirects; if the repository was renamed or transferred, use its new name", repo)
	case errors.As(err, &ue):
		log.Warn("upstream failed", "error", ue.Error())
		fail(w, http.StatusBadGateway, "GitHub answered %d %s for %s; try again later", ue.status, http.StatusText(ue.status), repo)
	case isTimeout(err):
		log.Warn("upstream timed out")
		fail(w, http.StatusGatewayTimeout, "the request for %s did not finish in time; try again later", repo)
	default:
		log.Warn("cannot reach upstream", "error", transportFailure(err))
		fail(w, http.StatusBadGateway, "cannot reach GitHub for %s; try again later", repo)
	}
}

// transportFailure says what kind of transport error err is. The error itself is not logged: its
// text can quote what the upstream sent, and a broken or hostile upstream can echo the credential.
func transportFailure(err error) string {
	var (
		dnsErr  *net.DNSError
		opErr   *net.OpError
		certErr *tls.CertificateVerificationError
		recErr  tls.RecordHeaderError
	)
	switch {
	case errors.As(err, &dnsErr):
		return "name lookup failed"
	case errors.As(err, &certErr):
		return "the upstream's certificate is not trusted"
	case errors.As(err, &recErr):
		return "the upstream does not speak TLS"
	case errors.As(err, &opErr):
		return "network error during " + opErr.Op
	}
	return "the upstream's answer is not valid HTTP"
}
