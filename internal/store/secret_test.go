package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestSecretIsRedacted(t *testing.T) {
	const value = "github_pat_do-not-print"
	s := NewSecret(value)
	type holder struct {
		Token Secret
	}
	// fmt prints unexported fields by reflection, without calling their methods.
	type private struct {
		token Secret
	}
	var out []string
	for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%10.3s"} {
		out = append(out, fmt.Sprintf(format, s), fmt.Sprintf(format, holder{s}), fmt.Sprintf(format, &holder{s}),
			fmt.Sprintf(format, private{s}), fmt.Sprintf(format, &private{s}), fmt.Sprintf(format, []Secret{s}))
	}
	out = append(out, fmt.Sprint(s), fmt.Sprintln(s), fmt.Errorf("wrapped: %v", s).Error())
	b, err := json.Marshal(holder{s})
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, string(b))
	var logs bytes.Buffer
	slog.New(slog.NewTextHandler(&logs, nil)).Info("x", "token", s, "holder", holder{s}, "private", private{s})
	slog.New(slog.NewJSONHandler(&logs, nil)).Info("x", "token", s, "holder", holder{s}, "private", private{s})
	out = append(out, logs.String())

	for _, o := range out {
		if strings.Contains(o, "do-not-print") {
			t.Errorf("a rendering holds the secret value (%d bytes)", len(o))
		}
	}
	if got := fmt.Sprint(s); got != "[redacted]" {
		t.Errorf("fmt.Sprint(secret) = %q, want [redacted]", got)
	}
	if s.Reveal() != value {
		t.Error("Reveal() does not return the value")
	}
}

func TestNewKey(t *testing.T) {
	for _, prefix := range []string{userKeyPrefix, adminTokenPrefix} {
		key, hash := newKey(prefix)
		k := key.Reveal()
		if !strings.HasPrefix(k, prefix) || len(k) != len(prefix)+64 {
			t.Errorf("newKey(%q) has the wrong shape (%d bytes)", prefix, len(k))
		}
		if want := sha256.Sum256([]byte(k)); !bytes.Equal(hash, want[:]) {
			t.Errorf("newKey(%q) hash is not SHA-256 of the key", prefix)
		}
		if got, ok := hashKey(prefix, key); !ok || !bytes.Equal(got, hash) {
			t.Errorf("hashKey(newKey(%q)) = %v, want the same hash", prefix, ok)
		}
		if other, _ := newKey(prefix); other == key {
			t.Errorf("newKey(%q) returned the same key twice", prefix)
		}
	}
}

func TestHashKeyRejectsMalformed(t *testing.T) {
	body := strings.Repeat("0123456789abcdef", 4)
	tests := []struct {
		name, prefix, key string
	}{
		{name: "empty", prefix: userKeyPrefix},
		{name: "prefix only", prefix: userKeyPrefix, key: "ghgw_"},
		{name: "admin token as user key", prefix: userKeyPrefix, key: "ghgwa_" + body},
		{name: "user key as admin token", prefix: adminTokenPrefix, key: "ghgw_" + body},
		{name: "upper-case prefix", prefix: userKeyPrefix, key: "GHGW_" + body},
		{name: "upper-case hex", prefix: userKeyPrefix, key: "ghgw_" + strings.ToUpper(body)},
		{name: "one character short", prefix: userKeyPrefix, key: "ghgw_" + body[1:]},
		{name: "one character long", prefix: userKeyPrefix, key: "ghgw_" + body + "0"},
		{name: "not hex", prefix: userKeyPrefix, key: "ghgw_" + body[1:] + "g"},
		{name: "white space", prefix: userKeyPrefix, key: " ghgw_" + body},
		{name: "huge", prefix: userKeyPrefix, key: "ghgw_" + strings.Repeat(body, 1<<14)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, ok := hashKey(tt.prefix, NewSecret(tt.key)); ok {
				t.Error("hashKey() accepted a malformed key")
			}
		})
	}
	if _, ok := hashKey(userKeyPrefix, NewSecret("ghgw_"+body)); !ok {
		t.Error("hashKey() rejected a well-formed key")
	}
}

func TestMatchHash(t *testing.T) {
	a, b := sha256.Sum256([]byte("a")), sha256.Sum256([]byte("b"))
	sameSelector := a
	sameSelector[len(sameSelector)-1] ^= 1
	tests := []struct {
		name   string
		stored [][]byte
		want   int
	}{
		{name: "no candidate", want: -1},
		{name: "match", stored: [][]byte{a[:]}, want: 0},
		{name: "other hash", stored: [][]byte{b[:]}, want: -1},
		{name: "same selector, other hash", stored: [][]byte{sameSelector[:]}, want: -1},
		{name: "second candidate", stored: [][]byte{sameSelector[:], a[:]}, want: 1},
		{name: "truncated stored hash", stored: [][]byte{a[:16]}, want: -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchHash(a[:], tt.stored); got != tt.want {
				t.Errorf("matchHash() = %d, want %d", got, tt.want)
			}
		})
	}
}
