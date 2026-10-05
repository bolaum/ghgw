package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"unicode/utf8"
)

// MaxCheckedBody bounds the bodies CheckBody reads: a review with dozens of line comments is a few
// KiB.
const MaxCheckedBody = 1 << 20

// ChecksBody reports whether operation name is forwarded only with a body CheckBody accepts: the
// path cannot tell a comment from an approval, nor a branch of the repository from a branch of
// another one.
func ChecksBody(name string) bool {
	return name == OpCreatePull || name == OpCreateReview
}

// The keys pulls.create takes: no head_repo, so the source is a branch of the repository itself.
var createPullKeys = []string{"title", "body", "head", "base", "draft", "maintainer_can_modify", "issue"}

// The examples in the reasons: what would work instead.
const (
	createPullExample = "gh api -X POST repos/{owner}/{repo}/pulls -f head=BRANCH -f base=main -f title=... -f body=..."
	reviewExample     = "gh api -X POST repos/{owner}/{repo}/pulls/NUMBER/reviews --input review.json, with " +
		`{"event": "COMMENT", "body": "...", "comments": [{"path": "FILE", "line": 1, "body": "..."}]}`
)

// CheckBody checks the query string and the body of a request for operation name, one ChecksBody
// reports. The error is the reason to deny the request, and says what would work. The checks are
// those of SPEC.md section 5.3: what GitHub reads must be what was checked, so the body is one JSON
// object in UTF-8 whose top-level keys are distinct even ignoring escapes and case, and no
// parameter comes from the query string.
func CheckBody(name, rawQuery string, body []byte) error {
	example := createPullExample
	if name == OpCreateReview {
		example = reviewExample
	}
	keys, fields, err := checkedFields(name, rawQuery, body)
	if err != nil {
		return fmt.Errorf("%w. For example: %s", err, example)
	}
	switch name {
	case OpCreatePull:
		for _, key := range keys {
			if !slices.Contains(createPullKeys, key) {
				return fmt.Errorf("%s takes only the keys %s and %s through ghgw, not %s: the source of a pull request is a branch of the same repository. For example: %s",
					name, strings.Join(createPullKeys[:len(createPullKeys)-1], ", "), createPullKeys[len(createPullKeys)-1], Printable(key), example)
			}
		}
		var head string
		if raw, ok := fields["head"]; !ok || !isJSONString(raw) || json.Unmarshal(raw, &head) != nil || strings.Contains(head, ":") {
			return fmt.Errorf("%s needs a head that is a branch of the same repository, without OWNER: ; ghgw does not open pull requests from other repositories. For example: %s",
				name, example)
		}
	case OpCreateReview:
		var event string
		if raw, ok := fields["event"]; !ok || !isJSONString(raw) || json.Unmarshal(raw, &event) != nil || event != "COMMENT" {
			return fmt.Errorf(`%s is forwarded only with "event": "COMMENT": ghgw does not approve, request changes or leave pending reviews. For example: %s`,
				name, example)
		}
	default:
		return fmt.Errorf("ghgw does not check the body of %s", Printable(name))
	}
	return nil
}

// checkedFields returns the top-level keys of body, a JSON object, decoded and in order, and its
// fields by key.
func checkedFields(name, rawQuery string, body []byte) ([]string, map[string]json.RawMessage, error) {
	switch {
	case rawQuery != "":
		return nil, nil, fmt.Errorf("%s takes no query string through ghgw; send every parameter in the JSON body", name)
	case len(body) > MaxCheckedBody:
		return nil, nil, fmt.Errorf("the body of %s is %d bytes, more than the %d ghgw reads", name, len(body), MaxCheckedBody)
	case !utf8.Valid(body):
		return nil, nil, fmt.Errorf("the body of %s is not valid UTF-8", name)
	}
	invalid := fmt.Errorf("the body of %s is not one JSON object", name)
	dec := json.NewDecoder(bytes.NewReader(body))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, nil, invalid
	}
	var keys []string
	fields := make(map[string]json.RawMessage)
	folded := make(map[string]bool)
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, nil, invalid
		}
		key, ok := tok.(string)
		if !ok {
			return nil, nil, invalid
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, nil, invalid
		}
		// GitHub might keep the first or the last of two equal keys; ghgw cannot know which.
		fold := strings.ToLower(key)
		if folded[fold] {
			return nil, nil, fmt.Errorf("the body of %s has the key %s more than once (keys are compared ignoring escapes and case)", name, Printable(key))
		}
		folded[fold] = true
		keys = append(keys, key)
		fields[key] = value
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, nil, invalid
	}
	// Nothing but white space may follow the object.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, nil, invalid
	}
	return keys, fields, nil
}

func isJSONString(raw json.RawMessage) bool {
	return len(raw) > 0 && raw[0] == '"'
}
