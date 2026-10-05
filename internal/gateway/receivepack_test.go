package gateway

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/bolaum/ghgw/internal/core"
)

// pkt returns s as one pkt-line.
func pkt(s string) string { return fmt.Sprintf("%04x%s", len(s)+4, s) }

const (
	zeroID  = "0000000000000000000000000000000000000000"
	oldID   = "1111111111111111111111111111111111111111"
	newID   = "2222222222222222222222222222222222222222"
	newID2  = "2222222222222222222222222222222222222222222222222222222222222222"
	zeroID2 = "0000000000000000000000000000000000000000000000000000000000000000"
	// gitCaps are the capabilities git 2.53 asks for when it pushes to GitHub.
	gitCaps = " report-status-v2 side-band-64k quiet object-format=sha1 agent=git/2.53.0"
)

func TestReadCommandList(t *testing.T) {
	longRef := "refs/heads/" + strings.Repeat("x", core.MaxRefNameLen-len("refs/heads/"))
	many := pkt(zeroID + " " + newID + " refs/heads/b0\x00" + gitCaps)
	for i := 1; i < core.MaxRefUpdates; i++ {
		many += pkt(fmt.Sprintf("%s %s refs/heads/b%d", zeroID, newID, i))
	}
	tests := []struct {
		name string
		list string
		want []core.RefUpdate
		// wantReport and wantSideband are the capabilities read.
		wantReport, wantSideband bool
		wantErr                  string
	}{
		{name: "one command as git sends it", list: pkt(oldID+" "+newID+" refs/heads/agent/x\x00"+gitCaps) + "0000",
			want: []core.RefUpdate{{Ref: "refs/heads/agent/x", Kind: core.UpdateRef}}, wantReport: true, wantSideband: true},
		{name: "create, update, delete", list: pkt(zeroID+" "+newID+" refs/heads/a\x00report-status") + pkt(oldID+" "+newID+" refs/heads/b") + pkt(oldID+" "+zeroID+" refs/heads/c") + "0000",
			want: []core.RefUpdate{{Ref: "refs/heads/a", Kind: core.CreateRef}, {Ref: "refs/heads/b", Kind: core.UpdateRef}, {Ref: "refs/heads/c", Kind: core.DeleteRef}}, wantReport: true},
		{name: "no capabilities", list: pkt(oldID+" "+newID+" refs/heads/a") + "0000",
			want: []core.RefUpdate{{Ref: "refs/heads/a", Kind: core.UpdateRef}}},
		{name: "capabilities with values", list: pkt(oldID+" "+newID+" refs/heads/a\x00report-status=x side-band-64k=") + "0000",
			want: []core.RefUpdate{{Ref: "refs/heads/a", Kind: core.UpdateRef}}, wantReport: true, wantSideband: true},
		{name: "side-band is not side-band-64k", list: pkt(oldID+" "+newID+" refs/heads/a\x00side-band report-status-v3") + "0000",
			want: []core.RefUpdate{{Ref: "refs/heads/a", Kind: core.UpdateRef}}},
		{name: "one trailing newline is dropped, as git does", list: pkt(oldID+" "+newID+" refs/heads/a\n") + pkt(oldID+" "+newID+" refs/heads/b\n\n") + "0000",
			want: []core.RefUpdate{{Ref: "refs/heads/a", Kind: core.UpdateRef}, {Ref: "refs/heads/b\n", Kind: core.UpdateRef}}},
		{name: "newline after the capabilities", list: pkt(oldID+" "+newID+" refs/heads/a\x00report-status\n") + "0000",
			want: []core.RefUpdate{{Ref: "refs/heads/a", Kind: core.UpdateRef}}, wantReport: true},
		{name: "shallow lines first", list: pkt("shallow "+oldID) + pkt("shallow "+newID+"\n") + pkt(oldID+" "+newID+" refs/heads/a") + "0000",
			want: []core.RefUpdate{{Ref: "refs/heads/a", Kind: core.UpdateRef}}},
		{name: "SHA-256", list: pkt(zeroID2+" "+newID2+" refs/heads/a\x00object-format=sha256") + "0000",
			want: []core.RefUpdate{{Ref: "refs/heads/a", Kind: core.CreateRef}}},
		// Names are checked by core, not here.
		{name: "any ref name", list: pkt(oldID+" "+newID+" refs/tags/v1") + pkt(oldID+" "+newID+" refs/heads/a b") + pkt(oldID+" "+newID+" ") + "0000",
			want: []core.RefUpdate{{Ref: "refs/tags/v1", Kind: core.UpdateRef}, {Ref: "refs/heads/a b", Kind: core.UpdateRef}, {Ref: "", Kind: core.UpdateRef}}},
		{name: "longest ref", list: pkt(oldID+" "+newID+" "+longRef) + "0000",
			want: []core.RefUpdate{{Ref: longRef, Kind: core.UpdateRef}}},
		{name: "no commands", list: "0000"},

		{name: "empty body", list: "", wantErr: errTruncated.reason},
		{name: "no flush", list: pkt(oldID + " " + newID + " refs/heads/a"), wantErr: errTruncated.reason},
		{name: "cut in a length", list: "00", wantErr: errTruncated.reason},
		{name: "cut in a line", list: pkt(oldID + " " + newID + " refs/heads/a")[:30], wantErr: errTruncated.reason},
		{name: "uppercase length", list: strings.ToUpper(pkt(oldID+" "+newID+" refs/heads/a/"+strings.Repeat("x", 120))) + "0000", wantErr: errMalformed.reason},
		{name: "length not hex", list: "00g0" + strings.Repeat("x", 12), wantErr: errMalformed.reason},
		{name: "delim packet", list: pkt(oldID+" "+newID+" refs/heads/a") + "0001" + "0000", wantErr: errMalformed.reason},
		{name: "response end packet", list: "0002", wantErr: errMalformed.reason},
		{name: "length 3", list: "0003", wantErr: errMalformed.reason},
		{name: "empty line", list: "0004" + "0000", wantErr: errMalformed.reason},
		{name: "line too long", list: fmt.Sprintf("%04x", pktMax+1) + strings.Repeat("x", pktMax), wantErr: errMalformed.reason},
		{name: "not a command", list: pkt("hello world refs/heads/a") + "0000", wantErr: errMalformed.reason},
		{name: "one id", list: pkt(oldID+" refs/heads/a") + "0000", wantErr: errMalformed.reason},
		{name: "short id", list: pkt(oldID[:39]+" "+newID+" refs/heads/a") + "0000", wantErr: errMalformed.reason},
		{name: "uppercase id", list: pkt(strings.ToUpper("abcdef"+oldID[6:])+" "+newID+" refs/heads/a") + "0000", wantErr: errMalformed.reason},
		{name: "ids of different lengths", list: pkt(oldID+" "+newID2+" refs/heads/a") + "0000", wantErr: errMalformed.reason},
		{name: "two zero ids", list: pkt(zeroID+" "+zeroID+" refs/heads/a") + "0000", wantErr: errMalformed.reason},
		{name: "double space", list: pkt(oldID+"  "+newID+" refs/heads/a") + "0000", wantErr: errMalformed.reason},
		{name: "capabilities on a later command", list: pkt(oldID+" "+newID+" refs/heads/a\x00report-status") + pkt(oldID+" "+newID+" refs/heads/b\x00side-band-64k") + "0000",
			wantErr: errMalformed.reason, wantReport: true},
		{name: "shallow line after a command", list: pkt(oldID+" "+newID+" refs/heads/a") + pkt("shallow "+oldID) + "0000", wantErr: errMalformed.reason},
		{name: "bad shallow line", list: pkt("shallow x") + "0000", wantErr: errMalformed.reason},
		{name: "signed push", list: pkt("push-cert\x00report-status side-band-64k") + pkt("certificate version 0.1\n") + "0000",
			wantErr: "signed pushes are not supported; push without --signed", wantReport: true, wantSideband: true},
		{name: "ref too long", list: pkt(oldID+" "+newID+" "+longRef+"x") + "0000",
			wantErr: "the push has a ref name longer than the 1024 bytes allowed; use a shorter name"},
		{name: "1000 updates", list: many + "0000", wantReport: true, wantSideband: true},
		{name: "1001 updates", list: many + pkt(zeroID+" "+newID+" refs/heads/last") + "0000", wantReport: true, wantSideband: true,
			wantErr: "the push has more than the 1000 ref updates allowed; push fewer refs at a time"},
		{name: "list too large", list: strings.Repeat(pkt("shallow "+oldID), maxCommandList/48+1) + "0000",
			wantErr: "the push's list of ref updates is larger than the 4194304 bytes ghgw reads; push fewer refs at a time"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const pack = "PACK and whatever follows"
			body := tt.list
			if tt.wantErr == "" {
				body += pack
			}
			// One byte at a time: no line may depend on how the body arrives.
			r := bufio.NewReader(iotest.OneByteReader(strings.NewReader(body)))
			c, err := readCommandList(r)
			if c.report != tt.wantReport || c.sideband != tt.wantSideband {
				t.Errorf("report, sideband = %v, %v; want %v, %v", c.report, c.sideband, tt.wantReport, tt.wantSideband)
			}
			if tt.wantErr != "" {
				var pe *protocolError
				if !errors.As(err, &pe) || pe.reason != tt.wantErr {
					t.Fatalf("readCommandList() = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("readCommandList() = %v", err)
			}
			if tt.name != "1000 updates" && !reflect.DeepEqual(c.updates, tt.want) {
				t.Errorf("updates = %+v, want %+v", c.updates, tt.want)
			}
			if string(c.raw) != tt.list {
				t.Errorf("raw = %q, want the list as sent", c.raw)
			}
			if rest, _ := io.ReadAll(r); string(rest) != pack {
				t.Errorf("left %q unread, want the pack", rest)
			}
		})
	}
}

// TestReadCommandListReadError tells a client that failed (a timeout) from a truncated list.
func TestReadCommandListReadError(t *testing.T) {
	failed := errors.New("i/o timeout")
	r := bufio.NewReader(io.MultiReader(strings.NewReader(pkt(oldID+" "+newID+" refs/heads/a")), iotest.ErrReader(failed)))
	if _, err := readCommandList(r); !errors.Is(err, failed) {
		t.Errorf("readCommandList() = %v, want %v", err, failed)
	}
}

func TestReports(t *testing.T) {
	updates := []core.RefUpdate{{Ref: "refs/heads/main"}, {Ref: "refs/heads/a\x1bb"}}
	reasons := []string{"push to the default branch is not allowed; allowed branches: agent/**", "another ref was rejected"}
	report := pkt("unpack ok\n") +
		pkt("ng refs/heads/main ghgw: push to the default branch is not allowed; allowed branches: agent/**\n") +
		pkt(`ng "refs/heads/a\x1bb" ghgw: another ref was rejected`+"\n") + "0000"
	whole := pkt("unpack ghgw: the push has more than the 1000 ref updates allowed\n") + "0000"
	tests := []struct {
		name string
		got  []byte
		want string
	}{
		{name: "per ref", got: refReport(updates, reasons, false), want: report},
		{name: "per ref, sideband", got: refReport(updates, reasons, true), want: pkt("\x01"+report) + "0000"},
		{name: "whole", got: wholeReport("the push has more than the 1000 ref updates allowed", false), want: whole},
		{name: "whole, sideband", got: wholeReport("the push has more than the 1000 ref updates allowed", true), want: pkt("\x01"+whole) + "0000"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.got) != tt.want {
				t.Errorf("report = %q, want %q", tt.got, tt.want)
			}
		})
	}
}

// TestReportSidebandPackets cuts a large report into sideband packets git can read.
func TestReportSidebandPackets(t *testing.T) {
	var updates []core.RefUpdate
	var reasons []string
	for i := range core.MaxRefUpdates {
		updates = append(updates, core.RefUpdate{Ref: fmt.Sprintf("refs/heads/%d/%s", i, strings.Repeat("x", 1000))})
		reasons = append(reasons, "another ref was rejected")
	}
	plain := refReport(updates, reasons, false)
	b := refReport(updates, reasons, true)
	var got []byte
	var buf [pktMax]byte
	r := bufio.NewReader(strings.NewReader(string(b)))
	for {
		p, err := readPkt(r, buf[:])
		if err != nil {
			t.Fatalf("readPkt() = %v", err)
		}
		if string(p) == "0000" {
			break
		}
		if p[4] != 1 {
			t.Fatalf("packet in band %d, want 1", p[4])
		}
		got = append(got, p[5:]...)
	}
	if string(got) != string(plain) {
		t.Error("the sideband does not carry the report")
	}
	if rest, _ := io.ReadAll(r); len(rest) != 0 {
		t.Errorf("%d bytes after the final flush", len(rest))
	}
}
