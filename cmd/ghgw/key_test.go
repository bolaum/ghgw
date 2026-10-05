package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestKeyNew(t *testing.T) {
	keyRE := regexp.MustCompile(`^key: (ghgw_[0-9a-f]{64})\nkey_hash: (sha256:[0-9a-f]{64})\n$`)
	out := mustRun(t, "", "key", "new")
	m := keyRE.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("key new = %q, want a key and its hash", out)
	}
	if h := sha256.Sum256([]byte(m[1])); m[2] != "sha256:"+hex.EncodeToString(h[:]) {
		t.Errorf("key_hash %s is not the SHA-256 of the key", m[2])
	}
	if out2 := mustRun(t, "", "key", "new"); out2 == out {
		t.Error("key new printed the same key twice")
	}

	path := filepath.Join(t.TempDir(), "agent.key")
	var got keyJSON
	if err := json.Unmarshal([]byte(mustRun(t, "", "key", "new", "--key-file", path, "--json")), &got); err != nil {
		t.Fatal(err)
	}
	if got.Key != "" || got.KeyFile != path {
		t.Errorf("key new --key-file --json = %+v, want the file and no key", got)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("key file mode = %04o, want 0600", perm)
	}
	data, _ := os.ReadFile(path)
	key, ok := strings.CutSuffix(string(data), "\n")
	if h := sha256.Sum256([]byte(key)); !ok || got.KeyHash != "sha256:"+hex.EncodeToString(h[:]) {
		t.Errorf("key file holds %d bytes that do not match key_hash", len(data))
	}

	out, _, err = run(t, "", "key", "new", "--key-file", path)
	if err == nil || !strings.Contains(err.Error(), "never replaces a key file") || out != "" {
		t.Errorf("key new over an existing key file: out %q, error %v", out, err)
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(after, data) {
		t.Error("key new replaced an existing key file")
	}
}
