package gateway

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net/http"

	"github.com/bolaum/ghgw/internal/core"
	"github.com/bolaum/ghgw/internal/store"
)

// push serves a push (POST git-receive-pack) of a user with write access to the repository: it
// reads the command list, decides every ref update with core and forwards the push only when all
// are allowed (SPEC.md section 5.2). A rejected push is answered with a receive-pack report, and
// nothing reaches GitHub.
func (g *Gateway) push(w http.ResponseWriter, r *http.Request, q gitRequest, snap *snapshot, user string, token store.Secret) {
	// GitHub would decode a compressed body, which ghgw would then have checked in another form.
	// git never compresses a push.
	if len(r.Header.Values("Content-Encoding")) > 0 {
		fail(w, http.StatusUnsupportedMediaType, "ghgw checks the ref updates of a push, so it takes pushes without Content-Encoding only; push with git")
		return
	}
	body := bufio.NewReaderSize(r.Body, pktMax)
	cmds, err := readCommandList(body)
	var pe *protocolError
	switch {
	case errors.As(err, &pe):
		rejectPush(w, body, cmds, http.StatusBadRequest, pe.reason, wholeReport(pe.reason, cmds.sideband))
		return
	case err != nil:
		// The client went away or was too slow: nobody reads an answer.
		return
	case len(cmds.updates) == 0:
		// git sends a command list alone, empty, to probe the connection before a large push.
		// receive-pack does nothing with it and answers nothing; ghgw does the same itself, so
		// the push authorizes nothing upstream.
		if drain(body) {
			writeResult(w, nil)
		}
		return
	}

	var d core.Decision
	if branch, err := g.defaultBranch(r.Context(), q.repo, token); err != nil {
		// Fail closed: the default branch rule cannot be checked.
		d = core.Decision{Reason: err.Error()}
		for _, u := range cmds.updates {
			d.Refs = append(d.Refs, core.RefDecision{Ref: u.Ref, Reason: err.Error()})
		}
	} else {
		d = snap.policy.Decide(core.Request{User: user, Repo: q.repo, Op: core.Push{DefaultBranch: branch, Updates: cmds.updates}})
	}
	if !d.Allowed {
		rejectPush(w, body, cmds, http.StatusForbidden, d.Reason, refReport(cmds.updates, d.RefReasons(), cmds.sideband))
		return
	}
	// Forward the command list as read, then the rest of the body as it comes.
	r.Body = readCloser{io.MultiReader(bytes.NewReader(cmds.raw), body), r.Body}
	g.forward(w, r, q, user, token)
}

type readCloser struct {
	io.Reader
	io.Closer
}

// rejectPush answers a push that is not forwarded with its report, or with status and reason when
// the client asked for no report.
func rejectPush(w http.ResponseWriter, body io.Reader, cmds *commandList, status int, reason string, report []byte) {
	if !drain(body) {
		return
	}
	if !cmds.report {
		fail(w, status, "%s", reason)
		return
	}
	writeResult(w, report)
}

// drain reads the rest of a push that is not forwarded, within the deadline of an answer: a client
// still sending its pack would not read the answer otherwise. It reports whether the body ended;
// if not, the client went away or was too slow, and nobody reads an answer.
func drain(body io.Reader) bool {
	_, err := io.Copy(io.Discard, body)
	return err == nil
}

// writeResult answers a push with b, as receive-pack would.
func writeResult(w http.ResponseWriter, b []byte) {
	h := w.Header()
	h.Set("Content-Type", "application/x-git-receive-pack-result")
	h.Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}
