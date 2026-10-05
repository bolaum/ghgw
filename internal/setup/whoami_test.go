package setup

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bolaum/ghgw/internal/store"
)

// tlsServer serves h over TLS and returns its URL and a transport that trusts it.
func tlsServer(t *testing.T, h http.HandlerFunc) (string, http.RoundTripper) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	return srv.URL, srv.Client().Transport
}

func TestWhoami(t *testing.T) {
	key, _ := store.NewUserKey()
	elsewhere, _ := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("a redirect was followed to %s", r.URL)
	})
	tests := []struct {
		name     string
		status   int
		header   http.Header
		body     string
		wantUser string
		wantErr  string
	}{
		{name: "identity", status: 200, body: `{"user":"rpi01-agent","groups":[],"grants":[]}`, wantUser: "rpi01-agent"},
		{name: "unknown key", status: 401, body: `{"message":"ghgw: unknown ghgw key; run ghgw setup again"}`,
			wantErr: "answered 401: unknown ghgw key; run ghgw setup again"},
		{name: "redirect", status: 302, header: http.Header{"Location": {elsewhere + "/_ghgw/whoami"}},
			wantErr: "answered 302 to /_ghgw/whoami, not as a ghgw gateway does; check the gateway URL"},
		{name: "not a gateway", status: 404, body: "<html>Not Found</html>",
			wantErr: "answered 404 to /_ghgw/whoami, not as a ghgw gateway does; check the gateway URL"},
		{name: "not an identity", status: 200, body: `{"login":"x"}`,
			wantErr: "with something that is not a ghgw identity"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url, rt := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/_ghgw/whoami" || r.Header.Get("Authorization") != "token "+key.Reveal() {
					t.Errorf("the gateway got %s with Authorization %q", r.URL, r.Header.Get("Authorization"))
				}
				for k, v := range tt.header {
					w.Header()[k] = v
				}
				w.WriteHeader(tt.status)
				fmt.Fprint(w, tt.body)
			})
			who, err := Whoami(context.Background(), rt, Config{URL: url, Key: key})
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("Whoami() = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil || who.User != tt.wantUser {
				t.Errorf("Whoami() = %+v, %v; want user %s", who, err, tt.wantUser)
			}
		})
	}

	t.Run("untrusted certificate", func(t *testing.T) {
		url, _ := tlsServer(t, func(http.ResponseWriter, *http.Request) {})
		_, err := Whoami(context.Background(), nil, Config{URL: url, Key: key})
		if err == nil || !strings.HasPrefix(err.Error(), "cannot reach the gateway at "+url+": tls: ") || !strings.HasSuffix(err.Error(), "trusts the gateway's certificate") {
			t.Errorf("Whoami() = %v, want a hint about the certificate", err)
		}
	})
}
