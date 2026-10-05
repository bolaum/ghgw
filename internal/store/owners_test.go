package store

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var timeZero time.Time

func TestOwners(t *testing.T) {
	ctx := context.Background()
	s, _, _ := openStore(t)
	expiry := time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)
	before := time.Now().Add(-time.Second)
	if err := s.AddOwner(ctx, "Acme", NewSecret("github_pat_one"), expiry); err != nil {
		t.Fatal(err)
	}
	if err := s.AddOwner(ctx, "bolaum", NewSecret("ghp_two"), timeZero); err != nil {
		t.Fatal(err)
	}
	owners, err := s.Owners(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(owners) != 2 || owners[0].Name != "Acme" || !owners[0].ExpiresAt.Equal(expiry) ||
		owners[1].Name != "bolaum" || !owners[1].ExpiresAt.IsZero() || owners[0].UpdatedAt.Before(before.Truncate(time.Second)) {
		t.Errorf("Owners() = %+v", owners)
	}

	// Owners match case-insensitively, like GitHub.
	if got, err := s.Credential(ctx, "acme"); err != nil || got.Reveal() != "github_pat_one" {
		t.Errorf("Credential(acme) error = %v, or the credential differs", err)
	}
	if err := s.RotateOwner(ctx, "ACME", NewSecret("github_pat_three"), timeZero); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Credential(ctx, "Acme"); err != nil || got.Reveal() != "github_pat_three" {
		t.Errorf("Credential() after rotation error = %v, or the credential differs", err)
	}
	if owners, _ := s.Owners(ctx); owners[0].Name != "Acme" || !owners[0].ExpiresAt.IsZero() {
		t.Errorf("after rotation, owner = %+v; want the name kept and no expiry", owners[0])
	}

	if err := s.DeleteOwner(ctx, "acme"); err != nil {
		t.Fatal(err)
	}
	_, err = s.Credential(ctx, "acme")
	wantErr(t, err, ErrNotFound, "ghgw has no credential for owner acme")
}

func TestOwnerErrors(t *testing.T) {
	ctx := context.Background()
	s, _, _ := openStore(t)
	if err := s.AddOwner(ctx, "acme", NewSecret("github_pat_x"), timeZero); err != nil {
		t.Fatal(err)
	}
	const secretPart = "SECRETPART"
	tests := []struct {
		name   string
		change func() error
		kind   error
		want   string
	}{
		{name: "duplicate", change: func() error { return s.AddOwner(ctx, "ACME", NewSecret("t"), timeZero) }, kind: ErrExists, want: "owner ACME already has a credential; rotate it instead"},
		{name: "rotate unknown", change: func() error { return s.RotateOwner(ctx, "nobody", NewSecret("t"), timeZero) }, kind: ErrNotFound, want: "owner nobody has no credential; add it first"},
		{name: "delete unknown", change: func() error { return s.DeleteOwner(ctx, "nobody") }, kind: ErrNotFound, want: "owner nobody has no credential"},
		{name: "invalid owner", change: func() error { return s.AddOwner(ctx, "a/b", NewSecret("t"), timeZero) }, kind: ErrInvalid, want: "owner a/b must be"},
		{name: "empty token", change: func() error { return s.AddOwner(ctx, "x", Secret{}, timeZero) }, kind: ErrInvalid, want: "the token must be 1 to 1024 characters"},
		{name: "token too long", change: func() error {
			return s.AddOwner(ctx, "x", NewSecret(secretPart+strings.Repeat("a", MaxTokenLen)), timeZero)
		}, kind: ErrInvalid, want: "1 to 1024"},
		{name: "token with a newline", change: func() error { return s.AddOwner(ctx, "x", NewSecret(secretPart+"\n"), timeZero) }, kind: ErrInvalid, want: "without spaces or line breaks"},
		{name: "token with CR LF", change: func() error { return s.RotateOwner(ctx, "acme", NewSecret(secretPart+"\r\nX-Evil: 1"), timeZero) }, kind: ErrInvalid, want: "visible ASCII"},
		{name: "token with a space", change: func() error { return s.AddOwner(ctx, "x", NewSecret("token "+secretPart), timeZero) }, kind: ErrInvalid, want: "visible ASCII"},
		{name: "token with a NUL", change: func() error { return s.AddOwner(ctx, "x", NewSecret(secretPart+"\x00"), timeZero) }, kind: ErrInvalid, want: "visible ASCII"},
		{name: "non-ASCII token", change: func() error { return s.AddOwner(ctx, "x", NewSecret(secretPart+"é"), timeZero) }, kind: ErrInvalid, want: "visible ASCII"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.change()
			wantErr(t, err, tt.kind, tt.want)
			if err != nil && strings.Contains(err.Error(), secretPart) {
				t.Error("the error quotes the token")
			}
		})
	}
	if got, err := s.Credential(ctx, "acme"); err != nil || got.Reveal() != "github_pat_x" {
		t.Errorf("a rejected rotation changed the credential (error = %v)", err)
	}
}

func sealedCredential(t *testing.T, s *Store, owner string) []byte {
	t.Helper()
	var sealed []byte
	if err := s.db.QueryRow("SELECT credential FROM owners WHERE name = ?", owner).Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	return sealed
}

func TestCredentialSealing(t *testing.T) {
	ctx := context.Background()
	s, _, _ := openStore(t)
	token := NewSecret("github_pat_same")
	if err := s.AddOwner(ctx, "acme", token, timeZero); err != nil {
		t.Fatal(err)
	}
	first := sealedCredential(t, s, "acme")
	if err := s.RotateOwner(ctx, "acme", token, timeZero); err != nil {
		t.Fatal(err)
	}
	second := sealedCredential(t, s, "acme")
	if len(first) != len(token.Reveal())+28 {
		t.Errorf("sealed credential is %d bytes, want the token plus a 12-byte nonce and a 16-byte tag", len(first))
	}
	// A random nonce per seal: the same token never seals to the same bytes.
	if bytes.Equal(first[:12], second[:12]) || bytes.Equal(first, second) {
		t.Error("sealing the same token twice gave the same nonce or ciphertext")
	}
}

func TestCredentialTampering(t *testing.T) {
	tests := []struct {
		name   string
		tamper func(t *testing.T, s *Store)
	}{
		{
			name: "ciphertext moved to another owner",
			tamper: func(t *testing.T, s *Store) {
				sealed := sealedCredential(t, s, "acme")
				if _, err := s.db.Exec("UPDATE owners SET credential = ? WHERE name = 'victim'", sealed); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "key check moved to an owner",
			tamper: func(t *testing.T, s *Store) {
				if _, err := s.db.Exec("UPDATE owners SET credential = (SELECT value FROM meta WHERE key = 'key_check') WHERE name = 'victim'"); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "flipped bit",
			tamper: func(t *testing.T, s *Store) {
				sealed := sealedCredential(t, s, "victim")
				sealed[len(sealed)-1] ^= 1
				if _, err := s.db.Exec("UPDATE owners SET credential = ? WHERE name = 'victim'", sealed); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "truncated",
			tamper: func(t *testing.T, s *Store) {
				if _, err := s.db.Exec("UPDATE owners SET credential = x'0102' WHERE name = 'victim'"); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			s, _, _ := openStore(t)
			if err := s.AddOwner(ctx, "acme", NewSecret("github_pat_acme"), timeZero); err != nil {
				t.Fatal(err)
			}
			if err := s.AddOwner(ctx, "victim", NewSecret("github_pat_victim"), timeZero); err != nil {
				t.Fatal(err)
			}
			tt.tamper(t, s)
			_, err := s.Credential(ctx, "victim")
			wantErr(t, err, nil, "the credential of owner victim was not sealed for it under this master key; rotate it")
		})
	}
}

// TestNoPlaintextSecretsInDatabase checks every database file, while the store is open (the WAL
// holds the latest writes) and after it is closed, for every secret and its hex body.
func TestNoPlaintextSecretsInDatabase(t *testing.T) {
	ctx := context.Background()
	s, dir, admin := openStore(t)
	key, err := s.CreateUser(ctx, "agent")
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := s.CreateUser(ctx, "rotated")
	if err != nil {
		t.Fatal(err)
	}
	newKey, err := s.RotateUserKey(ctx, "rotated")
	if err != nil {
		t.Fatal(err)
	}
	creds := []Secret{
		NewSecret("github_pat_11AAAAAAA0plaintextcredentialone"),
		NewSecret("github_pat_11BBBBBBB0plaintextcredentialtwo"),
		NewSecret("ghp_plaintextcredentialthreeXXXXXXXXXX"),
	}
	if err := s.AddOwner(ctx, "acme", creds[0], timeZero); err != nil {
		t.Fatal(err)
	}
	if err := s.RotateOwner(ctx, "acme", creds[1], timeZero); err != nil {
		t.Fatal(err)
	}
	if err := s.AddOwner(ctx, "bolaum", creds[2], timeZero); err != nil {
		t.Fatal(err)
	}
	deleted := sealedCredential(t, s, "bolaum")
	if err := s.DeleteOwner(ctx, "bolaum"); err != nil {
		t.Fatal(err)
	}

	needles := map[string]string{"credential": "plaintextcredential"}
	for i, c := range creds {
		needles["credential "+string(rune('1'+i))] = c.Reveal()
	}
	for name, k := range map[string]Secret{"user key": key, "rotated user key": rotated, "new user key": newKey, "admin token": admin} {
		needles[name] = k.Reveal()
		_, body, _ := strings.Cut(k.Reveal(), "_")
		needles[name+" body"] = body
		needles[name+" body prefix"] = body[:16]
	}

	scan := func(when string) {
		t.Helper()
		files, err := filepath.Glob(filepath.Join(dir, dbFile+"*"))
		if err != nil {
			t.Fatal(err)
		}
		var total int
		for _, f := range files {
			data, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			total += len(data)
			for name, needle := range needles {
				if bytes.Contains(data, []byte(needle)) {
					t.Errorf("%s: %s holds the plaintext %s", when, filepath.Base(f), name)
				}
			}
		}
		if total == 0 {
			t.Fatalf("%s: the database files are empty", when)
		}
	}
	scan("store open")
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	scan("store closed")
	// secure_delete: a deleted credential's ciphertext is not left in a free page of the database.
	if data := readFile(t, filepath.Join(dir, dbFile)); bytes.Contains(data, deleted) {
		t.Error("the database still holds the ciphertext of the deleted credential")
	}

	// The scan would miss nothing: the hash of a key is in the database, as stored.
	s2, _, err := reopen(t, dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := hashKey(userKeyPrefix, key)
	var n int
	if err := s2.db.QueryRow("SELECT count(*) FROM users WHERE key_hash = ?", hash).Scan(&n); err != nil || n != 1 {
		t.Errorf("the user key is not stored as its SHA-256 hash (count %d, error %v)", n, err)
	}
}
