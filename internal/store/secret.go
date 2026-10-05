package store

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"strings"
)

// Secret holds a ghgw key, an admin token or a GitHub credential. It prints as "[redacted]" with
// every fmt verb and in slog, and marshals to JSON as {}, so a secret reaches a log, an error or
// a response only through an explicit Reveal.
type Secret struct {
	// value is behind a pointer because fmt prints an unexported Secret field of another struct by
	// reflection, without calling Format: it then shows an address, never the value.
	value *string
}

const redacted = "[redacted]"

// NewSecret wraps s.
func NewSecret(s string) Secret { return Secret{value: &s} }

// Reveal returns the secret value. Call it only where the value itself is needed: injecting a
// credential upstream, or handing a new key to the admin once.
func (s Secret) Reveal() string {
	if s.value == nil {
		return ""
	}
	return *s.value
}

// IsZero reports whether s holds nothing.
func (s Secret) IsZero() bool { return s.Reveal() == "" }

// Format makes every fmt verb print "[redacted]".
func (Secret) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, redacted) }

// LogValue makes slog print "[redacted]".
func (Secret) LogValue() slog.Value { return slog.StringValue(redacted) }

// User keys and admin tokens are a prefix and 32 random bytes in lowercase hex. The prefixes tell
// them apart ("ghgwa_" does not start with "ghgw_") and let secret scanners find leaked ones.
const (
	userKeyPrefix    = "ghgw_"
	adminTokenPrefix = "ghgwa_"
	keyRandomBytes   = 32
)

// newKey returns a new key with prefix and its hash.
func newKey(prefix string) (Secret, []byte) {
	b := make([]byte, keyRandomBytes)
	_, _ = rand.Read(b) // never fails: crypto/rand aborts the program instead
	key := NewSecret(prefix + hex.EncodeToString(b))
	h := sha256.Sum256([]byte(key.Reveal()))
	return key, h[:]
}

// hashKey returns the hash of key, or false when key is not a well-formed key with prefix: such a
// key cannot exist, so it is unknown without a database lookup. The check also bounds the input.
func hashKey(prefix string, key Secret) ([]byte, bool) {
	body, ok := strings.CutPrefix(key.Reveal(), prefix)
	if !ok || len(body) != 2*keyRandomBytes {
		return nil, false
	}
	for _, c := range []byte(body) {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return nil, false
		}
	}
	h := sha256.Sum256([]byte(key.Reveal()))
	return h[:], true
}

// Keys are looked up by the first bytes of their hash (the selector) and then compared in full in
// constant time, so the database never compares a whole secret-derived value byte by byte.
const selectorBytes = 8

func selector(hash []byte) []byte { return hash[:selectorBytes] }

// matchHash returns the index of the stored hash equal to hash, or -1. It compares in constant
// time and looks at every candidate.
func matchHash(hash []byte, stored [][]byte) int {
	found := -1
	for i, s := range stored {
		if subtle.ConstantTimeCompare(hash, s) == 1 {
			found = i
		}
	}
	return found
}
