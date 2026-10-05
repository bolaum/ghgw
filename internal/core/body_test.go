package core

import (
	"strings"
	"testing"
)

func TestChecksBody(t *testing.T) {
	for name, want := range map[string]bool{
		"pulls.create": true, "pulls.create-review": true,
		"pulls.update": false, "issues.create-comment": false, "pulls.create-reply-for-review-comment": false,
	} {
		if got := ChecksBody(name); got != want {
			t.Errorf("ChecksBody(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestCheckBody(t *testing.T) {
	const (
		review     = "pulls.create-review"
		create     = "pulls.create"
		notComment = `is forwarded only with "event": "COMMENT"`
		notObject  = "is not one JSON object"
		twice      = "more than once"
		badHead    = "needs a head that is a branch of the same repository"
		onlyKeys   = "takes only the keys title, body, head, base, draft, maintainer_can_modify and issue through ghgw, not "
	)
	big := `{"event": "COMMENT", "body": "` + strings.Repeat("x", MaxCheckedBody) + `"}`
	tests := []struct {
		name, op, query, body string
		wantErr               string // empty: accepted
	}{
		{name: "comment review", op: review, body: `{"event": "COMMENT", "body": "Two problems.", "comments": [{"path": "a.go", "line": 1, "body": "x", "event": "APPROVE"}]}`},
		{name: "comment review, escaped", op: review, body: "{\"\\u0065vent\": \"COMM\\u0045NT\"}\n"},
		{name: "approve", op: review, body: `{"event": "APPROVE"}`, wantErr: notComment},
		{name: "request changes", op: review, body: `{"event": "REQUEST_CHANGES", "body": "no"}`, wantErr: notComment},
		{name: "lowercase comment", op: review, body: `{"event": "comment"}`, wantErr: notComment},
		{name: "no event (pending)", op: review, body: `{"body": "x"}`, wantErr: notComment},
		{name: "event not a string", op: review, body: `{"event": ["COMMENT"]}`, wantErr: notComment},
		{name: "event null", op: review, body: `{"event": null}`, wantErr: notComment},
		{name: "two equal events", op: review, body: `{"event": "COMMENT", "event": "COMMENT"}`, wantErr: twice},
		{name: "two conflicting events", op: review, body: `{"event": "COMMENT", "event": "APPROVE"}`, wantErr: twice},
		{name: "Event next to event", op: review, body: `{"event": "COMMENT", "Event": "APPROVE"}`, wantErr: twice},
		{name: "escaped event next to event", op: review, body: `{"event": "COMMENT", "\u0065vent": "APPROVE"}`, wantErr: twice},
		{name: "event in the query string", op: review, query: "event=APPROVE", body: `{"event": "COMMENT"}`, wantErr: "takes no query string"},
		{name: "invalid JSON", op: review, body: `{"event": "COMMENT"`, wantErr: notObject},
		{name: "trailing data", op: review, body: `{"event": "COMMENT"} {"event": "APPROVE"}`, wantErr: notObject},
		{name: "trailing garbage", op: review, body: `{"event": "COMMENT"}x`, wantErr: notObject},
		{name: "array", op: review, body: `[{"event": "COMMENT"}]`, wantErr: notObject},
		{name: "empty", op: review, body: ``, wantErr: notObject},
		{name: "comment in JSON", op: review, body: `{"event": "COMMENT" /* , "event": "APPROVE" */}`, wantErr: notObject},
		{name: "invalid UTF-8", op: review, body: "{\"event\": \"COMMENT\", \"body\": \"\xff\"}", wantErr: "is not valid UTF-8"},
		{name: "too large", op: review, body: big, wantErr: "more than the 1048576 ghgw reads"},

		{name: "branch of the repository", op: create, body: `{"head": "agent/fix-42", "base": "main", "title": "..."}`},
		{name: "every key", op: create, body: `{"title": "t", "body": "b", "head": "h", "base": "main", "draft": true, "maintainer_can_modify": false, "issue": 1}`},
		{name: "private fork", op: create, body: `{"head": "o:main", "head_repo": "o/secret", "base": "main"}`, wantErr: onlyKeys + "head_repo"},
		{name: "owner:branch", op: create, body: `{"head": "o:main", "base": "main"}`, wantErr: badHead},
		{name: "owner/repo:branch", op: create, body: `{"head": "o/secret:main", "base": "main"}`, wantErr: badHead},
		{name: "another user's branch", op: create, body: `{"head": "agent:fix", "base": "main"}`, wantErr: badHead},
		{name: "escaped colon", op: create, body: `{"head": "o\u003amain", "base": "main"}`, wantErr: badHead},
		{name: "head_repo alone", op: create, body: `{"head": "main", "head_repo": "bolaum/ghgw", "base": "main"}`, wantErr: onlyKeys + "head_repo"},
		{name: "Head_Repo", op: create, body: `{"head": "main", "Head_Repo": "o/secret"}`, wantErr: onlyKeys + "Head_Repo"},
		{name: "escaped head_repo", op: create, body: `{"head": "main", "he\u0061d_repo": "o/secret"}`, wantErr: onlyKeys + "head_repo"},
		{name: "unknown key", op: create, body: `{"head": "main", "labels": ["automerge"]}`, wantErr: onlyKeys + "labels"},
		{name: "two equal heads", op: create, body: `{"head": "agent/x", "head": "agent/x"}`, wantErr: twice},
		{name: "two conflicting heads", op: create, body: `{"head": "agent/x", "head": "o:main"}`, wantErr: twice},
		{name: "Head next to head", op: create, body: `{"head": "agent/x", "Head": "o:main"}`, wantErr: twice},
		{name: "no head", op: create, body: `{"base": "main", "title": "t"}`, wantErr: badHead},
		{name: "head not a string", op: create, body: `{"head": {"repo": "o/secret", "ref": "main"}}`, wantErr: badHead},
		{name: "head_repo in the query string", op: create, query: "head_repo=o/secret", body: `{"head": "main"}`, wantErr: "takes no query string"},
		{name: "invalid JSON", op: create, body: `{"head": main}`, wantErr: notObject},
		{name: "trailing data", op: create, body: `{"head": "main"}{"head_repo": "o/secret"}`, wantErr: notObject},
		{name: "too large", op: create, body: `{"head": "main", "body": "` + strings.Repeat("x", MaxCheckedBody) + `"}`, wantErr: "more than the 1048576 ghgw reads"},

		{name: "an operation without a body check", op: "pulls.update", body: `{}`, wantErr: "ghgw does not check the body of pulls.update"},
	}
	for _, tt := range tests {
		t.Run(tt.op+" "+tt.name, func(t *testing.T) {
			err := CheckBody(tt.op, tt.query, []byte(tt.body))
			switch {
			case tt.wantErr == "" && err != nil:
				t.Errorf("CheckBody() error = %v, want none", err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Errorf("CheckBody() error = %v, want %q", err, tt.wantErr)
			case err != nil && tt.op != "pulls.update" && !strings.Contains(err.Error(), "For example: gh api -X POST repos/{owner}/{repo}/pulls"):
				t.Errorf("CheckBody() error = %v, want an example of what works", err)
			}
		})
	}
}
