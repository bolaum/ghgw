package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseGitRequest(t *testing.T) {
	tests := []struct {
		name, method, target string
		body                 string
		chunked              bool
		want                 gitRequest
		wantRepo             string
		wantStatus           int
	}{
		{name: "advertisement", method: "GET", target: "/bolaum/ghgw.git/info/refs?service=git-upload-pack",
			want: gitRequest{service: uploadPack, advertisement: true}, wantRepo: "bolaum/ghgw"},
		{name: "without .git", method: "GET", target: "/bolaum/ghgw/info/refs?service=git-upload-pack",
			want: gitRequest{service: uploadPack, advertisement: true}, wantRepo: "bolaum/ghgw"},
		{name: "upper-case .GIT", method: "GET", target: "/bolaum/ghgw.GIT/info/refs?service=git-upload-pack",
			want: gitRequest{service: uploadPack, advertisement: true}, wantRepo: "bolaum/ghgw"},
		{name: "case kept", method: "POST", target: "/Bolaum/GHGW.git/git-upload-pack",
			want: gitRequest{service: uploadPack}, wantRepo: "Bolaum/GHGW"},
		{name: "receive-pack advertisement", method: "GET", target: "/bolaum/ghgw.git/info/refs?service=git-receive-pack",
			want: gitRequest{service: receivePack, advertisement: true}, wantRepo: "bolaum/ghgw"},
		{name: "receive-pack", method: "POST", target: "/bolaum/ghgw.git/git-receive-pack",
			want: gitRequest{service: receivePack}, wantRepo: "bolaum/ghgw"},
		{name: "dots in the name", method: "POST", target: "/bolaum/a.b_c-d/git-upload-pack",
			want: gitRequest{service: uploadPack}, wantRepo: "bolaum/a.b_c-d"},

		{name: "name ending in .git twice", method: "GET", target: "/bolaum/x.git.git/info/refs?service=git-upload-pack", wantStatus: 404},
		{name: "wiki", method: "GET", target: "/bolaum/ghgw.wiki.git/info/refs?service=git-upload-pack", wantStatus: 404},
		{name: "only .git", method: "GET", target: "/bolaum/.git/info/refs?service=git-upload-pack", wantStatus: 404},
		{name: "dot dot", method: "GET", target: "/bolaum/../info/refs?service=git-upload-pack", wantStatus: 404},
		{name: "dot", method: "POST", target: "/bolaum/./git-upload-pack", wantStatus: 404},
		{name: "empty owner", method: "POST", target: "//ghgw/git-upload-pack", wantStatus: 404},
		{name: "owner with underscore first", method: "POST", target: "/_ghgw/x/git-upload-pack", wantStatus: 404},
		{name: "escaped slash", method: "POST", target: "/bolaum%2Fghgw/x/git-upload-pack", wantStatus: 404},
		{name: "escaped letter", method: "POST", target: "/bolaum/gh%67w/git-upload-pack", wantStatus: 404},
		{name: "escaped dot", method: "POST", target: "/bolaum/x%2Egit/git-upload-pack", wantStatus: 404},
		{name: "space", method: "POST", target: "/bolaum/a%20b/git-upload-pack", wantStatus: 404},
		{name: "extra segment", method: "POST", target: "/bolaum/ghgw/x/git-upload-pack", wantStatus: 404},
		{name: "trailing slash", method: "POST", target: "/bolaum/ghgw/git-upload-pack/", wantStatus: 404},
		{name: "dumb http", method: "GET", target: "/bolaum/ghgw.git/HEAD", wantStatus: 404},
		{name: "dumb objects", method: "GET", target: "/bolaum/ghgw.git/objects/info/packs", wantStatus: 404},
		{name: "root", method: "GET", target: "/", wantStatus: 404},
		{name: "rest", method: "GET", target: "/api/v3/repos/bolaum/ghgw", wantStatus: 404},
		{name: "unknown service", method: "POST", target: "/bolaum/ghgw/git-upload-archive", wantStatus: 404},

		{name: "advertisement without service", method: "GET", target: "/bolaum/ghgw/info/refs", wantStatus: 400},
		{name: "unknown service query", method: "GET", target: "/bolaum/ghgw/info/refs?service=git-upload-archive", wantStatus: 400},
		{name: "extra query", method: "GET", target: "/bolaum/ghgw/info/refs?service=git-upload-pack&x=1", wantStatus: 400},
		{name: "escaped query", method: "GET", target: "/bolaum/ghgw/info/refs?service=git%2Dupload-pack", wantStatus: 400},
		{name: "service with query", method: "POST", target: "/bolaum/ghgw/git-upload-pack?x=1", wantStatus: 400},
		{name: "advertisement with POST", method: "POST", target: "/bolaum/ghgw/info/refs?service=git-upload-pack", wantStatus: 405},
		{name: "service with GET", method: "GET", target: "/bolaum/ghgw/git-upload-pack", wantStatus: 405},
		{name: "advertisement with a body", method: "GET", target: "/bolaum/ghgw/info/refs?service=git-upload-pack", body: "x", wantStatus: 400},
		{name: "advertisement with a chunked body", method: "GET", target: "/bolaum/ghgw/info/refs?service=git-upload-pack", chunked: true, wantStatus: 400},
		{name: "HEAD", method: "HEAD", target: "/bolaum/ghgw/info/refs?service=git-upload-pack", wantStatus: 405},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.target, strings.NewReader(tt.body))
			if tt.chunked {
				req.ContentLength = -1
			}
			got, err := parseGitRequest(req)
			if tt.wantStatus != 0 {
				if err == nil {
					t.Fatalf("parseGitRequest() = %+v, want status %d", got, tt.wantStatus)
				}
				if err.status != tt.wantStatus {
					t.Errorf("parseGitRequest() status = %d (%s), want %d", err.status, err.msg, tt.wantStatus)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseGitRequest() error = %d %s", err.status, err.msg)
			}
			if got.repo.String() != tt.wantRepo || got.service != tt.want.service || got.advertisement != tt.want.advertisement {
				t.Errorf("parseGitRequest() = %s %+v, want %s %+v", got.repo, got, tt.wantRepo, tt.want)
			}
		})
	}
}

func TestKeyFrom(t *testing.T) {
	const key = "ghgw_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	basic := func(user, password string) string {
		r := http.Request{Header: http.Header{}}
		r.SetBasicAuth(user, password)
		return r.Header.Get("Authorization")
	}
	tests := []struct {
		name      string
		headers   []string
		wantKey   string
		wantGiven bool
	}{
		{name: "none"},
		{name: "basic", headers: []string{basic("x", key)}, wantKey: key, wantGiven: true},
		{name: "basic, username ignored", headers: []string{basic("", key)}, wantKey: key, wantGiven: true},
		{name: "basic, lower-case scheme", headers: []string{"basic " + basic("x", key)[len("Basic "):]}, wantKey: key, wantGiven: true},
		{name: "token", headers: []string{"token " + key}, wantKey: key, wantGiven: true},
		{name: "Bearer", headers: []string{"Bearer " + key}, wantKey: key, wantGiven: true},
		{name: "bearer, upper case", headers: []string{"BEARER  " + key + " "}, wantKey: key, wantGiven: true},
		{name: "basic, not base64", headers: []string{"Basic " + key}, wantGiven: true},
		{name: "unknown scheme", headers: []string{"Digest " + key}, wantGiven: true},
		{name: "key alone", headers: []string{key}, wantGiven: true},
		{name: "empty", headers: []string{""}, wantGiven: true},
		{name: "two headers", headers: []string{"token " + key, "token " + key}, wantGiven: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, given := keyFrom(http.Header{"Authorization": tt.headers})
			if got.Reveal() != tt.wantKey || given != tt.wantGiven {
				t.Errorf("keyFrom() = %q, %v, want %q, %v", got.Reveal(), given, tt.wantKey, tt.wantGiven)
			}
		})
	}
}
