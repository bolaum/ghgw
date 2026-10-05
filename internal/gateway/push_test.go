package gateway

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/bolaum/ghgw/internal/core"
)

// apiAnswer answers like GitHub's API for a repository whose default branch is main.
func apiAnswer(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = io.WriteString(w, `{"id":1,"name":"pushable","default_branch":"main","owner":{"login":"bolaum"}}`)
}

const (
	receivePackPath = "/bolaum/pushable.git/git-receive-pack"
	// pack stands for the pack after the command list; ghgw never reads it.
	pack = "PACK\x00\x00\x00\x02\x00\x00\x00\x01 not a real pack"
	// guidance is the end of the reason of a push the policy rejects.
	guidance = "; allowed branches: agent/**"
)

// command is one command line of a push, the capabilities after the first.
func command(oldID, newID, ref string) string { return oldID + " " + newID + " " + ref }

// pushBody is a push as git sends it: its commands, the first with caps, then a flush and a pack.
func pushBody(caps string, commands ...string) string {
	var b strings.Builder
	for i, c := range commands {
		if i == 0 {
			c += "\x00" + caps
		}
		b.WriteString(pkt(c))
	}
	return b.String() + "0000" + pack
}

// report returns the report of a rejected push, in the sideband.
func report(lines ...string) string {
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(pkt(l + "\n"))
	}
	return pkt("\x01"+b.String()+"0000") + "0000"
}

// receivePacks returns the pushes the upstream got.
func (f *fakeUpstream) receivePacks() []string {
	reqs, bodies := f.got()
	var pushes []string
	for i, r := range reqs {
		if strings.HasSuffix(r.URL.Path, "/git-receive-pack") {
			pushes = append(pushes, string(bodies[i]))
		}
	}
	return pushes
}

func TestPush(t *testing.T) {
	e := newTestEnv(t)
	update := func(ref string) string { return command(oldID, newID, ref) }
	ng := func(ref, reason string) string { return "ng " + ref + " ghgw: " + reason }
	tests := []struct {
		name string
		body string
		// header is added to the request.
		header http.Header
		// wantStatus and wantBody are the gateway's answer when the push is not forwarded; an
		// allowed push gets the upstream's.
		wantForward bool
		wantStatus  int
		wantBody    string
	}{
		{name: "create a branch", body: pushBody(gitCaps, command(zeroID, newID, "refs/heads/agent/x")), wantForward: true},
		{name: "update and delete branches", body: pushBody(gitCaps, update("refs/heads/agent/x"), command(oldID, zeroID, "refs/heads/agent/y/z")), wantForward: true},
		{name: "no report asked", body: pushBody("", update("refs/heads/agent/x")), wantForward: true},

		{name: "default branch", body: pushBody(gitCaps, update("refs/heads/main")),
			wantStatus: 200, wantBody: report("unpack ok", ng("refs/heads/main", "push to the default branch is not allowed"+guidance))},
		{name: "default branch in another case", body: pushBody(gitCaps, update("refs/heads/MAIN")),
			wantStatus: 200, wantBody: report("unpack ok", ng("refs/heads/MAIN", "push to the default branch is not allowed"+guidance))},
		{name: "delete the default branch", body: pushBody(gitCaps, command(oldID, zeroID, "refs/heads/main")),
			wantStatus: 200, wantBody: report("unpack ok", ng("refs/heads/main", "deleting the default branch is not allowed"+guidance))},
		{name: "tag", body: pushBody(gitCaps, command(zeroID, newID, "refs/tags/v1")),
			wantStatus: 200, wantBody: report("unpack ok", ng("refs/tags/v1", "pushing tags is not allowed"+guidance))},
		{name: "other branch", body: pushBody(gitCaps, update("refs/heads/feature")),
			wantStatus: 200, wantBody: report("unpack ok", ng("refs/heads/feature", "push to branch feature is not allowed"+guidance))},
		{name: "notes", body: pushBody(gitCaps, update("refs/notes/commits")),
			wantStatus: 200, wantBody: report("unpack ok", ng("refs/notes/commits", "pushing refs/notes/commits is not allowed, only branches can be pushed"+guidance))},
		{name: "invalid ref name", body: pushBody(gitCaps, update("refs/heads/agent/a..b")),
			wantStatus: 200, wantBody: report("unpack ok", ng("refs/heads/agent/a..b", `invalid ref name refs/heads/agent/a..b: cannot contain ".."`+guidance))},
		{name: "ref name with a control character", body: pushBody(gitCaps, update("refs/heads/agent/\x1b[31m")),
			wantStatus: 200, wantBody: report("unpack ok", ng(`"refs/heads/agent/\x1b[31m"`, `invalid ref name "refs/heads/agent/\x1b[31m": cannot contain '\x1b'`+guidance))},
		{name: "all or nothing", body: pushBody(gitCaps, update("refs/heads/agent/x"), update("refs/heads/main"), update("refs/tags/v1")),
			wantStatus: 200, wantBody: report("unpack ok",
				ng("refs/heads/agent/x", "another ref was rejected"),
				ng("refs/heads/main", "push to the default branch is not allowed"+guidance),
				ng("refs/tags/v1", "pushing tags is not allowed"))},
		{name: "report without sideband", body: pushBody("report-status", update("refs/heads/main")),
			wantStatus: 200, wantBody: pkt("unpack ok\n") + pkt(ng("refs/heads/main", "push to the default branch is not allowed"+guidance)+"\n") + "0000"},
		{name: "no report asked, rejected", body: pushBody("side-band-64k", update("refs/heads/main")),
			wantStatus: 403, wantBody: "ghgw: push to the default branch is not allowed" + guidance + "\n"},

		{name: "probe", body: "0000", wantStatus: 200},
		{name: "no commands", body: pkt("shallow "+oldID) + "0000" + pack, wantStatus: 200},
		{name: "malformed, report asked", body: pkt(update("refs/heads/agent/x")+"\x00"+gitCaps) + pkt(update("refs/heads/agent/y")+"\x00report-status") + "0000" + pack,
			wantStatus: 200, wantBody: report("unpack ghgw: " + errMalformed.reason)},
		{name: "malformed first line", body: pkt("hello") + "0000" + pack,
			wantStatus: 400, wantBody: "ghgw: " + errMalformed.reason + "\n"},
		{name: "truncated", body: pkt(update("refs/heads/agent/x") + "\x00" + gitCaps),
			wantStatus: 200, wantBody: report("unpack ghgw: " + errTruncated.reason)},
		{name: "signed push", body: pkt("push-cert\x00"+gitCaps) + pkt("certificate version 0.1\n") + pkt(update("refs/heads/main")+"\n") + pkt("push-cert-end\n") + "0000" + pack,
			wantStatus: 200, wantBody: report("unpack ghgw: signed pushes are not supported; push without --signed")},
		{name: "compressed", body: pushBody(gitCaps, update("refs/heads/agent/x")), header: http.Header{"Content-Encoding": {"gzip"}},
			wantStatus: 415, wantBody: "ghgw: ghgw checks the ref updates of a push, so it takes pushes without Content-Encoding only; push with git\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e.upstream.set(gitAnswer)
			header := http.Header{"Content-Type": {"application/x-git-receive-pack-request"}}
			for k, v := range tt.header {
				header[k] = v
			}
			resp, body := e.do(t, "POST", receivePackPath, "rpi01-agent", strings.NewReader(tt.body), header)
			pushes := e.upstream.receivePacks()
			if tt.wantForward {
				if resp.StatusCode != 200 || body != "upstream body" {
					t.Errorf("got %d %q, want the upstream's answer", resp.StatusCode, body)
				}
				if len(pushes) != 1 || pushes[0] != tt.body {
					t.Errorf("the upstream got %q, want the push exactly as sent", pushes)
				}
				return
			}
			if resp.StatusCode != tt.wantStatus || body != tt.wantBody {
				t.Errorf("got %d %q\nwant %d %q", resp.StatusCode, body, tt.wantStatus, tt.wantBody)
			}
			if want := "application/x-git-receive-pack-result"; tt.wantStatus == 200 && resp.Header.Get("Content-Type") != want {
				t.Errorf("Content-Type = %q, want %q", resp.Header.Get("Content-Type"), want)
			}
			if len(pushes) != 0 {
				t.Errorf("the upstream got %d pushes, want none", len(pushes))
			}
		})
	}
}

// TestPushChunked forwards a push of unknown length as it was sent, after the command list.
func TestPushChunked(t *testing.T) {
	e := newTestEnv(t)
	want := pkt("shallow "+oldID) + pkt(command(zeroID, newID, "refs/heads/agent/x")+"\x00"+gitCaps+"\n") + "0000" + pkt("ci.skip") + "0000" + pack + strings.Repeat("x", 1<<20)
	// A MultiReader has no length: the request is chunked.
	resp, body := e.do(t, "POST", receivePackPath, "rpi01-agent", io.MultiReader(strings.NewReader(want)), nil)
	if resp.StatusCode != 200 || body != "upstream body" {
		t.Fatalf("got %d %q, want the upstream's answer", resp.StatusCode, body)
	}
	if pushes := e.upstream.receivePacks(); len(pushes) != 1 || pushes[0] != want {
		t.Errorf("the upstream got %d pushes, want the push exactly as sent", len(pushes))
	}
}

// TestPushReadOnly denies a push without write access before its body is read or the default
// branch looked up.
func TestPushReadOnly(t *testing.T) {
	e := newTestEnv(t)
	resp, body := e.do(t, "POST", "/bolaum/ghgw.git/git-receive-pack", "rpi01-agent", strings.NewReader(pushBody(gitCaps, command(oldID, newID, "refs/heads/agent/x"))), nil)
	if want := "ghgw: rpi01-agent has read-only access to bolaum/ghgw; pushing needs a grant with access write\n"; resp.StatusCode != 403 || body != want {
		t.Errorf("got %d %q, want 403 %q", resp.StatusCode, body, want)
	}
	if reqs, _ := e.upstream.got(); len(reqs) != 0 {
		t.Errorf("the upstream got %d requests, want none", len(reqs))
	}
}

func TestPushDefaultBranchLookup(t *testing.T) {
	e := newTestEnv(t)
	e.gw.limits.branchTTL = 0
	e.gw.limits.lookup = 200 * time.Millisecond
	api := func(status int, body string, header ...string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasPrefix(r.URL.Path, "/repos/") {
				gitAnswer(w, r)
				return
			}
			for i := 0; i+1 < len(header); i += 2 {
				w.Header().Set(header[i], header[i+1])
			}
			w.WriteHeader(status)
			_, _ = io.WriteString(w, body)
		}
	}
	const repo = "bolaum/pushable"
	// A broken or hostile upstream can echo the credential anywhere.
	echo := "upstream says " + ownerToken
	tests := []struct {
		name    string
		handler http.HandlerFunc
		// wantReason is the reason of both refs, or empty when the push is forwarded or gets
		// wantBody.
		wantReason, wantBody string
	}{
		{name: "another default branch", handler: api(200, `{"default_branch":"trunk","x":"`+echo+`"}`, "Content-Type", "application/json")},
		{name: "the default branch", handler: api(200, `{"default_branch":"agent/x"}`),
			wantBody: report("unpack ok", "ng refs/heads/agent/x ghgw: push to the default branch is not allowed"+guidance, "ng refs/heads/agent/y ghgw: another ref was rejected")},
		{name: "rate limited", handler: api(403, echo, "X-RateLimit-Remaining", "0"),
			wantReason: "GitHub's rate limit for the credential of owner bolaum is used up, so the push to bolaum/pushable cannot be checked; try again later"},
		{name: "too many requests", handler: api(429, echo),
			wantReason: "GitHub's rate limit for the credential of owner bolaum is used up, so the push to bolaum/pushable cannot be checked; try again later"},
		{name: "credential refused", handler: api(401, echo),
			wantReason: "GitHub refused the credential of owner bolaum for bolaum/pushable (401 Unauthorized) when ghgw looked up its default branch; ask the admin to check that it is valid (ghgw owner list) and can read bolaum/pushable"},
		{name: "forbidden", handler: api(403, echo),
			wantReason: "GitHub refused the credential of owner bolaum for bolaum/pushable (403 Forbidden) when ghgw looked up its default branch; ask the admin to check that it is valid (ghgw owner list) and can read bolaum/pushable"},
		{name: "not found", handler: api(404, echo),
			wantReason: "GitHub has no repository bolaum/pushable that the credential of owner bolaum can read; check the name, or ask the admin to give the credential access to it"},
		{name: "renamed", handler: api(301, echo, "Location", "https://api.github.com/repositories/1"),
			wantReason: "GitHub redirected the request for bolaum/pushable, and ghgw does not follow redirects; if the repository was renamed or transferred, use its new name"},
		{name: "server error", handler: api(502, echo),
			wantReason: "GitHub answered 502 Bad Gateway when ghgw looked up the default branch of bolaum/pushable, so the push cannot be checked; try again later"},
		{name: "not JSON", handler: api(200, "<html>"+echo),
			wantReason: "GitHub did not say which branch of bolaum/pushable is the default, so the push cannot be checked; try again later"},
		{name: "no default branch", handler: api(200, `{"default_branch":null}`),
			wantReason: "GitHub did not say which branch of bolaum/pushable is the default, so the push cannot be checked; try again later"},
		{name: "default branch too long", handler: api(200, `{"default_branch":"`+strings.Repeat("x", 1<<19)+`"}`),
			wantReason: "the default branch of bolaum/pushable is unknown or invalid, so the push cannot be checked; try again"},
		{name: "invalid default branch", handler: api(200, `{"default_branch":"a..b"}`),
			wantReason: "the default branch of bolaum/pushable is unknown or invalid, so the push cannot be checked; try again"},
		{name: "too slow", handler: func(w http.ResponseWriter, r *http.Request) {
			<-r.Context().Done()
		}, wantReason: "looking up the default branch of bolaum/pushable took too long, so the push cannot be checked; try again later"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e.upstream.set(tt.handler)
			push := pushBody(gitCaps, command(oldID, newID, "refs/heads/agent/x"), command(oldID, newID, "refs/heads/agent/y"))
			resp, body := e.do(t, "POST", receivePackPath, "rpi01-agent", strings.NewReader(push), nil)
			reqs, _ := e.upstream.got()
			if len(reqs) == 0 || reqs[0].URL.Path != "/repos/"+repo || reqs[0].Method != "GET" {
				t.Fatalf("the upstream got %v, want the lookup first", reqs)
			}
			if got := reqs[0].Header.Get("Authorization"); got != "Bearer "+ownerToken {
				t.Errorf("the lookup has Authorization %q, want the owner's credential", got)
			}
			pushes := e.upstream.receivePacks()
			if tt.wantReason == "" && tt.wantBody == "" {
				if resp.StatusCode != 200 || body != "upstream body" || len(pushes) != 1 {
					t.Errorf("got %d %q and %d pushes upstream, want the push forwarded", resp.StatusCode, body, len(pushes))
				}
				return
			}
			want := tt.wantBody
			if want == "" {
				want = report("unpack ok", "ng refs/heads/agent/x ghgw: "+tt.wantReason, "ng refs/heads/agent/y ghgw: "+tt.wantReason)
			}
			if resp.StatusCode != 200 || body != want {
				t.Errorf("got %d %q\nwant %q", resp.StatusCode, body, want)
			}
			if len(pushes) != 0 {
				t.Errorf("the upstream got %d pushes, want none", len(pushes))
			}
		})
	}
	if strings.Contains(e.logs.String(), ownerToken) {
		t.Error("the log holds the owner's credential")
	}
	for _, entry := range e.gw.branches.entries {
		if len(entry.branch) > core.MaxRefNameLen {
			t.Errorf("a default branch of %d bytes is held, want none longer than a ref", len(entry.branch))
		}
	}
}

// TestPushDefaultBranchCache looks the default branch up once per repository, whatever the case
// of its name, until the answer expires.
func TestPushDefaultBranchCache(t *testing.T) {
	e := newTestEnv(t)
	lookups := func() int {
		reqs, _ := e.upstream.got()
		n := 0
		for _, r := range reqs {
			if strings.HasPrefix(r.URL.Path, "/repos/") {
				n++
			}
		}
		return n
	}
	push := func(path string) {
		t.Helper()
		resp, body := e.do(t, "POST", path, "rpi01-agent", strings.NewReader(pushBody(gitCaps, command(oldID, newID, "refs/heads/agent/x"))), nil)
		if resp.StatusCode != 200 || body != "upstream body" {
			t.Fatalf("got %d %q, want the push forwarded", resp.StatusCode, body)
		}
	}
	e.upstream.set(gitAnswer)
	push(receivePackPath)
	push("/BOLAUM/Pushable.git/git-receive-pack")
	if n := lookups(); n != 1 {
		t.Errorf("%d lookups for two pushes, want 1", n)
	}
	e.gw.limits.branchTTL = 0
	e.gw.branches = branchCache{}
	e.upstream.set(gitAnswer)
	push(receivePackPath)
	push(receivePackPath)
	if n := lookups(); n != 2 {
		t.Errorf("%d lookups for two pushes once the answer expires at once, want 2", n)
	}
}

// TestBranchCacheBounded drops expired answers, or all of them, when the cache is full.
func TestBranchCacheBounded(t *testing.T) {
	var c branchCache
	now := time.Now()
	for i := range maxBranchCache {
		expires := now.Add(time.Minute)
		if i%2 == 0 {
			expires = now
		}
		c.put(fmt.Sprint(i), "main", now, expires)
	}
	c.put("new", "main", now, now.Add(time.Minute))
	if len(c.entries) != maxBranchCache/2+1 {
		t.Errorf("%d entries, want the expired ones dropped", len(c.entries))
	}
	for len(c.entries) < maxBranchCache {
		c.put(fmt.Sprintf("live %d", len(c.entries)), "main", now, now.Add(time.Minute))
	}
	c.put("newer", "main", now, now.Add(time.Minute))
	if b, ok := c.get("newer", now); len(c.entries) != 1 || !ok || b != "main" {
		t.Errorf("%d entries, want only the newest once full of live answers", len(c.entries))
	}
}
