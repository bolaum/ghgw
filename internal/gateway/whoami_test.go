package gateway

import (
	"net/http"
	"testing"
)

func TestWhoami(t *testing.T) {
	e := newTestEnv(t)
	tests := []struct {
		name, method, path, user string
		wantStatus               int
		// wantBody is the whole JSON answer, or the message of an error.
		wantBody string
	}{
		{name: "user with groups", method: "GET", path: "/_ghgw/whoami", user: "rpi01-agent", wantStatus: 200,
			wantBody: `{"user":"rpi01-agent","groups":["agents"],"grants":[` +
				`{"id":1,"holder":{"kind":"group","name":"agents"},"repos":["bolaum/*"],"access":"read","push":[],"api":"none"},` +
				`{"id":3,"holder":{"kind":"user","name":"rpi01-agent"},"repos":["bolaum/pushable"],"access":"write","push":["agent/**"],"api":"none"}]}` + "\n"},
		{name: "user without groups", method: "GET", path: "/_ghgw/whoami", user: "acme-agent", wantStatus: 200,
			wantBody: `{"user":"acme-agent","groups":[],"grants":[{"id":2,"holder":{"kind":"user","name":"acme-agent"},"repos":["acme/app"],"access":"read","push":[],"api":"none"}]}` + "\n"},
		{name: "disabled user", method: "GET", path: "/_ghgw/whoami", user: "off-agent", wantStatus: 403,
			wantBody: "ghgw: user off-agent is disabled; ask the admin to enable it"},
		{name: "no key", method: "GET", path: "/_ghgw/whoami", wantStatus: 401,
			wantBody: "ghgw: this gateway needs a ghgw key; ask the admin for one and run ghgw setup with it"},
		{name: "not GET", method: "POST", path: "/_ghgw/whoami", user: "rpi01-agent", wantStatus: 405,
			wantBody: "ghgw: /_ghgw/whoami is read with GET"},
		{name: "unknown endpoint", method: "GET", path: "/_ghgw/doctor", user: "rpi01-agent", wantStatus: 404,
			wantBody: "ghgw: unknown ghgw endpoint; ghgw serves GET /_ghgw/whoami"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, body := e.restDo(t, tt.method, tt.path, tt.user, nil, nil)
			if resp.StatusCode != tt.wantStatus {
				t.Errorf("status = %d, want %d", resp.StatusCode, tt.wantStatus)
			}
			got := body
			if resp.StatusCode != http.StatusOK {
				got = message(t, resp, body)
			}
			if got != tt.wantBody {
				t.Errorf("answer = %s\nwant %s", got, tt.wantBody)
			}
			e.checkNoUpstream(t)
		})
	}
}
