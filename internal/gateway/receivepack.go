package gateway

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/bolaum/ghgw/internal/core"
)

// A push (git's receive-pack request, protocol v0 and v1; v2 has no push) starts with its command
// list, then has the push options, when negotiated, and the pack:
//
//	*PKT-LINE("shallow" SP oid) PKT-LINE(command NUL capabilities) *PKT-LINE(command) flush-pkt
//	command = old-oid SP new-oid SP refname
//
// ghgw reads the command list only, and more strictly than git: whatever it accepts, git reads as
// the same commands. Nothing after the flush is a command for git, so the rest is not read.

const (
	// pktMax is the longest pkt-line git reads, its 4-byte length included.
	pktMax = 65520
	// maxCommandList bounds the command list in bytes, shallow lines included. 1000 updates of
	// the longest refs with SHA-256 ids and the longest capability line take about 1.2 MB.
	maxCommandList = 4 << 20
)

// commandList is the command list of a push, as read.
type commandList struct {
	updates []core.RefUpdate
	// raw is the command list exactly as the client sent it, its flush included: what ghgw
	// checked is what it forwards, never a list written again from updates.
	raw []byte
	// capsKnown is whether the first command, which carries the capabilities, was read. report
	// is whether the client asked for a report (report-status or report-status-v2), sideband
	// whether it gets it in the sideband (side-band-64k).
	capsKnown, report, sideband bool
}

// protocolError is a command list ghgw does not forward: malformed, truncated or over a limit. Its
// reason reads after "ghgw: ".
type protocolError struct {
	reason string
}

func (e *protocolError) Error() string { return e.reason }

var (
	errTruncated = &protocolError{"the push ended before its list of ref updates did; try again"}
	errMalformed = &protocolError{"the push's list of ref updates is malformed; push with git"}
)

// readCommandList reads the command list of a push from r, up to and including its flush. It
// returns a *protocolError for a list ghgw does not accept, and any other error when reading
// failed (the client went away or was too slow). The list read so far is returned with an error,
// so that the answer can use the client's capabilities.
func readCommandList(r *bufio.Reader) (*commandList, error) {
	c := &commandList{}
	var buf [pktMax]byte
	for {
		pkt, err := readPkt(r, buf[:])
		if err != nil {
			return c, err
		}
		if len(c.raw)+len(pkt) > maxCommandList {
			return c, &protocolError{fmt.Sprintf("the push's list of ref updates is larger than the %d bytes ghgw reads; push fewer refs at a time", maxCommandList)}
		}
		c.raw = append(c.raw, pkt...)
		if len(pkt) == 4 && string(pkt) == "0000" {
			return c, nil
		}
		if err := c.add(pkt[4:]); err != nil {
			return c, err
		}
	}
}

// readPkt reads one pkt-line into buf and returns it, its length included. A flush is "0000";
// git's other special packets (delim, response end) have no place in a command list.
func readPkt(r io.Reader, buf []byte) ([]byte, error) {
	if _, err := io.ReadFull(r, buf[:4]); err != nil {
		return nil, readErr(err)
	}
	n := 0
	for _, c := range buf[:4] {
		switch {
		case '0' <= c && c <= '9':
			n = n<<4 | int(c-'0')
		case 'a' <= c && c <= 'f':
			n = n<<4 | int(c-'a'+10)
		default:
			return nil, errMalformed
		}
	}
	switch {
	case n == 0:
		return buf[:4], nil
	case n < 4 || n > pktMax:
		return nil, errMalformed
	}
	if _, err := io.ReadFull(r, buf[4:n]); err != nil {
		return nil, readErr(err)
	}
	return buf[:n], nil
}

// readErr makes a body that ends too soon a truncated command list.
func readErr(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return errTruncated
	}
	return err
}

// add adds one line of the command list: a shallow line before the first command, or a command.
func (c *commandList) add(line []byte) error {
	// git drops one trailing newline from every line it reads.
	line = bytes.TrimSuffix(line, []byte("\n"))
	if !c.capsKnown {
		if oid, ok := bytes.CutPrefix(line, []byte("shallow ")); ok {
			if !isOID(oid) {
				return errMalformed
			}
			return nil
		}
		var caps []byte
		line, caps, _ = bytes.Cut(line, []byte{0})
		c.capsKnown = true
		for _, cap := range strings.Fields(string(caps)) {
			switch cap {
			case "report-status", "report-status-v2":
				c.report = true
			case "side-band-64k":
				c.sideband = true
			}
		}
		if string(line) == "push-cert" {
			// git would read the commands from the certificate.
			return &protocolError{"signed pushes are not supported; push without --signed"}
		}
	}
	if len(c.updates) == core.MaxRefUpdates {
		return &protocolError{fmt.Sprintf("the push has more than the %d ref updates allowed; push fewer refs at a time", core.MaxRefUpdates)}
	}
	oldID, rest, ok1 := bytes.Cut(line, []byte(" "))
	newID, ref, ok2 := bytes.Cut(rest, []byte(" "))
	// Capabilities come with the first command only (its NUL was cut above); git would read them
	// on any line.
	if !ok1 || !ok2 || !isOID(oldID) || len(newID) != len(oldID) || !isOID(newID) || bytes.IndexByte(ref, 0) >= 0 {
		return errMalformed
	}
	if len(ref) > core.MaxRefNameLen {
		return &protocolError{fmt.Sprintf("the push has a ref name longer than the %d bytes allowed; use a shorter name", core.MaxRefNameLen)}
	}
	u := core.RefUpdate{Ref: string(ref), Kind: core.UpdateRef}
	switch oldZero, newZero := isZero(oldID), isZero(newID); {
	case oldZero && newZero:
		return errMalformed
	case oldZero:
		u.Kind = core.CreateRef
	case newZero:
		u.Kind = core.DeleteRef
	}
	c.updates = append(c.updates, u)
	return nil
}

// isOID reports whether b is an object ID as git writes it: SHA-1 or SHA-256, lowercase hex.
func isOID(b []byte) bool {
	if len(b) != 40 && len(b) != 64 {
		return false
	}
	for _, c := range b {
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f') {
			return false
		}
	}
	return true
}

func isZero(oid []byte) bool {
	return len(bytes.Trim(oid, "0")) == 0
}

// The report of a push ghgw rejects itself, in the format of git's report-status:
//
//	PKT-LINE("unpack" SP ("ok" / error)) *PKT-LINE("ng" SP refname SP reason) flush-pkt
//
// With side-band-64k it travels in band 1, cut into packets, followed by a flush.

// refReport returns the report of a push rejected ref by ref: git shows each reason with its ref
// ("! [remote rejected] main -> main (ghgw: ...)"). reasons has one entry per update.
func refReport(updates []core.RefUpdate, reasons []string, sideband bool) []byte {
	b := appendPkt(nil, "unpack ok\n")
	for i, u := range updates {
		b = appendPkt(b, "ng "+core.Printable(u.Ref)+" ghgw: "+reasons[i]+"\n")
	}
	return finishReport(b, sideband)
}

// wholeReport returns the report of a push rejected as a whole, without a result per ref: git
// shows the reason as "remote unpack failed: ghgw: ...".
func wholeReport(reason string, sideband bool) []byte {
	return finishReport(appendPkt(nil, "unpack ghgw: "+reason+"\n"), sideband)
}

func finishReport(b []byte, sideband bool) []byte {
	b = append(b, "0000"...)
	if !sideband {
		return b
	}
	var out []byte
	for len(b) > 0 {
		n := min(len(b), pktMax-5)
		out = appendPkt(out, "\x01"+string(b[:n]))
		b = b[n:]
	}
	return append(out, "0000"...)
}

// appendPkt appends s as one pkt-line. Reasons and rendered refs are bounded far below pktMax.
func appendPkt(b []byte, s string) []byte {
	return append(fmt.Appendf(b, "%04x", len(s)+4), s...)
}
