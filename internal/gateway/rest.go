package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/bolaum/ghgw/internal/core"
	"github.com/bolaum/ghgw/internal/store"
)

// gh reaches the REST API of a GitHub Enterprise host under apiPrefix, and GraphQL at graphQLPath.
const (
	apiPrefix   = "/api/v3"
	graphQLPath = "/api/graphql"
)

// Only these headers pass between gh and GitHub's API, in each direction; Link and Location pass
// rewritten to the gateway. The client's Authorization holds its ghgw key, a method override could
// turn an allowed request into another one, and GitHub's headers about the credential
// (github-authentication-token-expiration, X-OAuth-Scopes) are not the agent's business.
var (
	restRequestHeaders  = []string{"Accept", "Accept-Encoding", "Content-Type", "If-Modified-Since", "If-None-Match", "User-Agent", "X-Github-Api-Version"}
	restResponseHeaders = []string{
		"Cache-Control", "Content-Encoding", "Content-Length", "Content-Type", "Etag", "Expires", "Last-Modified", "Retry-After", "Vary",
		"X-Github-Media-Type", "X-Github-Request-Id",
		"X-Ratelimit-Limit", "X-Ratelimit-Remaining", "X-Ratelimit-Reset", "X-Ratelimit-Resource", "X-Ratelimit-Used",
	}
	// logResponseHeaders pass from the storage host a job log is downloaded from.
	logResponseHeaders = []string{"Content-Length", "Content-Type"}
)

// restCall is a REST request as parsed and decided once: everything forwarded is built from it.
type restCall struct {
	user string
	// repo is zero for an operation that is not repository-scoped.
	repo core.Repo
	path core.RESTPath
	op   string
	// token is the owner's credential; zero for an operation that is not repository-scoped, which
	// is forwarded without one: the path names no owner whose credential it could use.
	token store.Secret
	// body is the checked body of an operation core.ChecksBody names, nil for any other.
	body []byte
	// base is the gateway's URL as the client reached it, which Link and Location are rewritten to.
	base string
}

// what names the call in messages.
func (c restCall) what() string {
	if c.repo.IsZero() {
		return c.op
	}
	return c.op + " on " + core.Printable(c.repo.String())
}

// serveREST serves a REST request whose path below apiPrefix is apiPath: authenticate, parse the
// path once, decide on it, check the body when the operation needs it, then forward.
func (g *Gateway) serveREST(w http.ResponseWriter, r *http.Request, apiPath string) {
	snap, user, ok := g.authenticate(w, r, failJSON)
	if !ok {
		return
	}
	path, err := core.ParseRESTPath(apiPath)
	if err != nil {
		failJSON(w, http.StatusBadRequest, "%s", err)
		return
	}
	repo, err := path.Repo()
	if err != nil {
		failJSON(w, http.StatusNotFound, "%s", err)
		return
	}
	d := snap.policy.Decide(core.Request{User: user, Repo: repo, Op: core.RESTRequest{Method: r.Method, Path: path}})
	if !d.Allowed {
		failJSON(w, http.StatusForbidden, "%s", d.Reason)
		return
	}
	if r.Method == http.MethodGet && r.ContentLength != 0 {
		failJSON(w, http.StatusBadRequest, "GET requests take no body; send the parameters in the query string")
		return
	}
	if r.ContentLength > g.limits.restBody {
		restBodyTooLarge(w, g.limits.restBody)
		return
	}
	setDeadline(w, g.limits.restRequest)
	call := restCall{user: user, repo: repo, path: path, op: d.Operation, base: gatewayBase(r)}
	if core.ChecksBody(call.op) {
		if call.body, ok = readChecked(w, r, call.op); !ok {
			return
		}
	} else {
		r.Body = http.MaxBytesReader(w, r.Body, g.limits.restBody)
	}
	if !repo.IsZero() {
		if call.token, ok = g.credential(w, r, repo, failJSON); !ok {
			return
		}
	}
	g.forwardREST(w, r, call)
}

// readChecked reads the body of operation op whole and checks it; GitHub gets exactly these bytes.
func readChecked(w http.ResponseWriter, r *http.Request, op string) ([]byte, bool) {
	body, err := io.ReadAll(io.LimitReader(r.Body, core.MaxCheckedBody+1))
	switch {
	case err != nil:
		failJSON(w, http.StatusBadRequest, "cannot read the body of %s; try again", op)
		return nil, false
	case len(body) > core.MaxCheckedBody:
		restBodyTooLarge(w, core.MaxCheckedBody)
		return nil, false
	}
	if err := core.CheckBody(op, r.URL.RawQuery, body); err != nil {
		failJSON(w, http.StatusForbidden, "%s", err)
		return nil, false
	}
	return body, true
}

func restBodyTooLarge(w http.ResponseWriter, limit int64) {
	failJSON(w, http.StatusRequestEntityTooLarge, "the request body is larger than the %d bytes ghgw forwards", limit)
}

// gatewayBase returns the gateway's URL as the client reached it. A client that sends another Host
// only gets links to that host.
func gatewayBase(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	return scheme + "://" + r.Host
}

// forwardREST sends the call to GitHub's API with the owner's credential and streams the answer
// back. The upstream URL is the API URL and the canonical path, never the request's path.
func (g *Gateway) forwardREST(w http.ResponseWriter, r *http.Request, call restCall) {
	target, err := url.Parse(g.apiURL.String() + call.path.String())
	if err != nil {
		failJSON(w, http.StatusBadRequest, "the API path cannot be forwarded")
		return
	}
	target.RawQuery = r.URL.RawQuery
	ctx, cancel := context.WithTimeout(r.Context(), g.limits.restRequest)
	defer cancel()
	r = r.WithContext(ctx)
	log := g.log.With("user", call.user, "repo", call.repo.String(), "operation", call.op)
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL = target
			pr.Out.Host = ""
			pr.Out.Header = make(http.Header)
			copyHeaders(pr.Out.Header, pr.In.Header, restRequestHeaders)
			pr.Out.Trailer = nil
			if call.body != nil {
				pr.Out.Body = io.NopCloser(bytes.NewReader(call.body))
				pr.Out.ContentLength = int64(len(call.body))
				pr.Out.TransferEncoding = nil
				// GitHub reads the bytes that were checked as the JSON they were checked as.
				pr.Out.Header.Set("Content-Type", "application/json; charset=utf-8")
			}
			if !call.token.IsZero() {
				pr.Out.Header.Set("Authorization", "Bearer "+call.token.Reveal())
			}
		},
		Transport:      g.transport,
		ModifyResponse: func(resp *http.Response) error { return g.restAnswer(resp, call) },
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			g.restUpstreamFailed(w, r, call, log, err)
		},
		ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	proxy.ServeHTTP(&finalWriter{ResponseWriter: w}, r)
}

// Failures of an answer that is not passed on. They hold nothing GitHub wrote, so they can be
// logged.
var (
	errRedirectedAway = errors.New("upstream redirected to another host")
	errAnswerTooLarge = errors.New("upstream answer too large")
)

// logError is why a job log could not be downloaded from the storage host GitHub redirected to.
type logError struct{ reason string }

func (e *logError) Error() string { return e.reason }

// restAnswer filters and rewrites GitHub's answer. GitHub's own errors (403, 404, 422, ...) pass
// on: they tell the agent what GitHub thinks of the request. A 401 does not: it is about the
// owner's credential, and gh would blame its ghgw key.
func (g *Gateway) restAnswer(resp *http.Response, call restCall) error {
	if resp.StatusCode == http.StatusUnauthorized {
		return &upstreamError{status: resp.StatusCode}
	}
	if call.op == core.OpDownloadJobLogs && isRedirect(resp.StatusCode) {
		return g.followLog(resp)
	}
	h := make(http.Header)
	copyHeaders(h, resp.Header, restResponseHeaders)
	if loc := resp.Header.Get("Location"); loc != "" {
		rewritten, ok := g.toGateway(resp.Request.URL, loc, call, false)
		switch {
		case ok:
			h.Set("Location", rewritten)
		case isRedirect(resp.StatusCode):
			return errRedirectedAway
		}
	}
	if links := rewriteLinks(resp.Header.Values("Link"), func(u string) (string, bool) {
		return g.toGateway(resp.Request.URL, u, call, true)
	}); links != "" {
		h.Set("Link", links)
	}
	resp.Header = h
	// Not announced; finalWriter drops them when they arrive.
	resp.Trailer = nil
	return capBody(resp, g.limits.restResponse)
}

func isRedirect(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}

// followLog downloads a job log from the signed storage URL GitHub redirected to, and makes it the
// answer, so agents never get that URL. One hop, https only, and a request of its own: neither the
// owner's credential nor any header of the agent's request goes to the storage host. An
// http.Client would keep Authorization for subdomains, other ports and http on the same host.
func (g *Gateway) followLog(resp *http.Response) error {
	loc, err := resp.Request.URL.Parse(resp.Header.Get("Location"))
	if err != nil || loc.Scheme != "https" || loc.Host == "" || loc.User != nil {
		return &logError{"GitHub redirected the job log to a URL that is not https"}
	}
	loc.Fragment = ""
	req, err := http.NewRequestWithContext(resp.Request.Context(), http.MethodGet, loc.String(), nil)
	if err != nil {
		return &logError{"GitHub redirected the job log to a URL ghgw cannot request"}
	}
	stored, err := g.transport.RoundTrip(req)
	if err != nil {
		return err
	}
	if stored.StatusCode != http.StatusOK {
		stored.Body.Close()
		return &logError{fmt.Sprintf("the log storage answered %d %s", stored.StatusCode, http.StatusText(stored.StatusCode))}
	}
	resp.Body.Close()
	h := make(http.Header)
	copyHeaders(h, stored.Header, logResponseHeaders)
	resp.StatusCode, resp.Header, resp.Body, resp.ContentLength, resp.Trailer = http.StatusOK, h, stored.Body, stored.ContentLength, nil
	return capBody(resp, g.limits.restResponse)
}

// toGateway rewrites raw, a URL in GitHub's answer to the request at base, to the same URL on the
// gateway, so gh sends its next request (a page, a redirect) to the gateway with its ghgw key, and
// that request gets a decision and a credential of its own. Only URLs on the API host are
// rewritten; ok is false for any other. Pagination links name the repository by ID
// (repositories/1296269/issues?page=2), a path ghgw cannot decide on: in links, the ID is the
// repository of the request, whose path they get. A redirect keeps the ID: it is where GitHub
// sends a request for a renamed or transferred repository, and the decision on it says so.
func (g *Gateway) toGateway(base *url.URL, raw string, call restCall, link bool) (string, bool) {
	u, err := base.Parse(raw)
	if err != nil || u.Scheme != "https" || !strings.EqualFold(u.Host, g.apiURL.Host) || u.User != nil {
		return "", false
	}
	path := u.EscapedPath()
	if link && !call.repo.IsZero() {
		if rest, ok := cutRepositoryID(path); ok {
			path = "/repos/" + call.repo.String() + rest
		}
	}
	out := call.base + apiPrefix + path
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	return out, true
}

// cutRepositoryID returns what follows /repositories/{id} in path.
func cutRepositoryID(path string) (string, bool) {
	rest, ok := strings.CutPrefix(path, "/repositories/")
	if !ok {
		return "", false
	}
	id, rest, _ := strings.Cut(rest, "/")
	if id == "" || strings.TrimLeft(id, "0123456789") != "" {
		return "", false
	}
	if rest != "" {
		rest = "/" + rest
	}
	return rest, true
}

// rewriteLinks rewrites the URLs of Link header values (`<url>; rel="next", <url>; rel="last"`)
// with rewrite and joins them into one value. A link whose URL is not rewritten, and anything that
// does not parse, are dropped.
func rewriteLinks(values []string, rewrite func(string) (string, bool)) string {
	var out []string
	for _, v := range values {
		for {
			v = strings.TrimLeft(v, " \t,")
			if !strings.HasPrefix(v, "<") {
				break
			}
			end := strings.IndexByte(v, '>')
			if end < 0 {
				break
			}
			target := v[1:end]
			v = v[end+1:]
			// The parameters run to the next comma outside a quoted string.
			i, quoted := 0, false
			for ; i < len(v) && (quoted || v[i] != ','); i++ {
				if v[i] == '"' {
					quoted = !quoted
				}
			}
			params := strings.TrimSpace(v[:i])
			v = v[i:]
			if u, ok := rewrite(target); ok {
				out = append(out, "<"+u+">"+params)
			}
		}
	}
	return strings.Join(out, ", ")
}

// capBody bounds the body of resp to limit bytes: an answer announced larger is refused, and one
// that grows larger is cut, which aborts the answer.
func capBody(resp *http.Response, limit int64) error {
	if resp.ContentLength > limit {
		return errAnswerTooLarge
	}
	resp.Body = &cappedBody{ReadCloser: resp.Body, left: limit}
	return nil
}

type cappedBody struct {
	io.ReadCloser
	left int64
}

func (b *cappedBody) Read(p []byte) (int, error) {
	if b.left == 0 {
		// At the limit: only the end of the body may follow.
		var probe [1]byte
		n, err := b.ReadCloser.Read(probe[:])
		if n > 0 {
			return 0, errAnswerTooLarge
		}
		return 0, err
	}
	if int64(len(p)) > b.left {
		p = p[:b.left]
	}
	n, err := b.ReadCloser.Read(p)
	b.left -= int64(n)
	return n, err
}

// restUpstreamFailed answers a REST request GitHub did not serve, with what the agent can do about
// it.
func (g *Gateway) restUpstreamFailed(w http.ResponseWriter, r *http.Request, call restCall, log *slog.Logger, err error) {
	what := call.what()
	var ue *upstreamError
	var le *logError
	var mbe *http.MaxBytesError
	switch {
	case r.Context().Err() != nil && !errors.Is(r.Context().Err(), context.DeadlineExceeded):
		// The client went away; nobody reads an answer.
		return
	case errors.As(err, &mbe):
		restBodyTooLarge(w, mbe.Limit)
	case errors.As(err, &ue) && !call.repo.IsZero():
		log.Warn("upstream refused the owner's credential", "error", ue.Error())
		failJSON(w, http.StatusBadGateway, "GitHub refused the credential of owner %s for %s (%d %s); ask the admin to check that it is valid (ghgw owner list)",
			core.Printable(call.repo.Owner()), what, ue.status, http.StatusText(ue.status))
	case errors.As(err, &ue):
		log.Warn("upstream refused a request without a credential", "error", ue.Error())
		failJSON(w, http.StatusBadGateway, "GitHub refused %s (%d %s); try again later", what, ue.status, http.StatusText(ue.status))
	case errors.Is(err, errRedirectedAway):
		log.Warn("upstream failed", "error", err.Error())
		failJSON(w, http.StatusBadGateway, "GitHub redirected %s to another host, and ghgw follows no redirect there", what)
	case errors.Is(err, errAnswerTooLarge):
		log.Warn("upstream failed", "error", err.Error())
		failJSON(w, http.StatusBadGateway, "GitHub's answer to %s is larger than the %d bytes ghgw passes on", what, g.limits.restResponse)
	case errors.As(err, &le):
		log.Warn("job log download failed", "error", le.Error())
		failJSON(w, http.StatusBadGateway, "cannot download the job log for %s: %s; try again later", what, le.reason)
	case isTimeout(err):
		log.Warn("upstream timed out")
		failJSON(w, http.StatusGatewayTimeout, "%s did not finish in time; try again later", what)
	default:
		log.Warn("cannot reach upstream", "error", transportFailure(err))
		failJSON(w, http.StatusBadGateway, "cannot reach GitHub for %s; try again later", what)
	}
}

// failJSON answers a REST request that is not forwarded the way GitHub answers errors, so gh shows
// the message: "gh: ghgw: ... (HTTP 403)".
func failJSON(w http.ResponseWriter, status int, format string, args ...any) {
	writeJSON(w, status, struct {
		Message string `json:"message"`
	}{"ghgw: " + fmt.Sprintf(format, args...)})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// graphQLGuidance is what an agent gets for any GraphQL request (SPEC.md sections 5.4 and 8).
const graphQLGuidance = "ghgw: GraphQL is not supported yet. Use the REST API through `gh api`, e.g.\n" +
	"gh api repos/{owner}/{repo}/pulls -f title=... -f head=... -f base=..."

// serveGraphQL answers every GraphQL request with a GraphQL error that gh prints, and forwards
// nothing.
func (g *Gateway) serveGraphQL(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := g.authenticate(w, r, failJSON); !ok {
		return
	}
	type graphQLError struct {
		Message string `json:"message"`
	}
	writeJSON(w, http.StatusOK, struct {
		Data   any            `json:"data"`
		Errors []graphQLError `json:"errors"`
	}{Errors: []graphQLError{{graphQLGuidance}}})
}
