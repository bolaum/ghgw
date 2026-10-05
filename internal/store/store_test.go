package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// openStore opens a store in a new state directory and closes it at the end of the test. It
// returns the first admin token, read from the file Open wrote it to.
func openStore(t *testing.T) (s *Store, dir string, adminToken Secret) {
	t.Helper()
	dir = filepath.Join(t.TempDir(), "state")
	s, tokenPath, err := Open(context.Background(), dir, Options{})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { s.Close() })
	if want := filepath.Join(dir, adminTokenFile); tokenPath != want {
		t.Fatalf("first Open() admin token path = %q, want %q", tokenPath, want)
	}
	return s, dir, readAdminToken(t, dir)
}

// readAdminToken returns the token in the admin-token file of dir, which ends in a newline.
func readAdminToken(t *testing.T, dir string) Secret {
	t.Helper()
	token, ok := strings.CutSuffix(string(readFile(t, filepath.Join(dir, adminTokenFile))), "\n")
	if !ok {
		t.Fatal("admin-token does not end in a newline")
	}
	return NewSecret(token)
}

// reopen opens the store in dir again, after a first Open.
func reopen(t *testing.T, dir string, opts Options) (*Store, string, error) {
	t.Helper()
	s, tokenPath, err := Open(context.Background(), dir, opts)
	if err == nil {
		t.Cleanup(func() { s.Close() })
	}
	return s, tokenPath, err
}

func TestOpenFirstStart(t *testing.T) {
	ctx := context.Background()
	s, dir, token := openStore(t)
	if _, ok := hashKey(adminTokenPrefix, token); !ok {
		t.Fatal("admin-token does not hold a well-formed admin token")
	}
	if err := s.AuthenticateAdmin(ctx, token); err != nil {
		t.Errorf("AuthenticateAdmin(first token) error = %v", err)
	}
	if _, err := s.CreateUser(ctx, "agent"); err != nil { // writes, so the WAL files exist
		t.Fatal(err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o700 {
		t.Errorf("state directory mode = %04o, want 0700", perm)
	}
	for _, name := range []string{dbFile, dbFile + "-wal", dbFile + "-shm", masterKeyFile, adminTokenFile} {
		fi, err := os.Lstat(filepath.Join(dir, name))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if perm := fi.Mode().Perm(); !fi.Mode().IsRegular() || perm != 0o600 {
			t.Errorf("%s: mode = %v, want a regular file with mode 0600", name, fi.Mode())
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Errorf("temporary file %s left in the state directory", e.Name())
		}
	}
}

func TestOpenAgain(t *testing.T) {
	ctx := context.Background()
	s, dir, token := openStore(t)
	key, err := s.CreateUser(ctx, "agent")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AddOwner(ctx, "acme", NewSecret("github_pat_again"), time.Time{}); err != nil {
		t.Fatal(err)
	}
	masterKey := readFile(t, filepath.Join(dir, masterKeyFile))
	s.Close()

	s2, tokenPath, err := reopen(t, dir, Options{})
	if err != nil {
		t.Fatalf("second Open() error = %v", err)
	}
	if tokenPath != "" {
		t.Error("second Open returned an admin token path; only the first start creates a token")
	}
	if !bytes.Equal(readFile(t, filepath.Join(dir, masterKeyFile)), masterKey) {
		t.Error("second Open changed the master key file")
	}
	if err := s2.AuthenticateAdmin(ctx, token); err != nil {
		t.Errorf("AuthenticateAdmin(first token) after reopening: %v", err)
	}
	if _, err := s2.AuthenticateUser(ctx, key); err != nil {
		t.Errorf("AuthenticateUser() after reopening: %v", err)
	}
	if got, err := s2.Credential(ctx, "acme"); err != nil || got.Reveal() != "github_pat_again" {
		t.Errorf("Credential() after reopening: error = %v, or the credential differs", err)
	}
}

func TestOpenRefusesUnsafeState(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, dir string)
		want  string
	}{
		{
			name:  "directory readable by others",
			setup: func(t *testing.T, dir string) { chmod(t, dir, 0o755) },
			want:  "run chmod 700 " + "<dir>",
		},
		{
			name:  "directory open to the group",
			setup: func(t *testing.T, dir string) { chmod(t, dir, 0o710) },
			want:  "accessible by group or others (mode 0710)",
		},
		{
			name:  "master key readable by the group",
			setup: func(t *testing.T, dir string) { chmod(t, filepath.Join(dir, masterKeyFile), 0o640) },
			want:  "run chmod 600 <dir>/master.key",
		},
		{
			name:  "admin token readable by others",
			setup: func(t *testing.T, dir string) { chmod(t, filepath.Join(dir, adminTokenFile), 0o604) },
			want:  "<dir>/admin-token is accessible by group or others",
		},
		{
			name: "master key is a symbolic link",
			setup: func(t *testing.T, dir string) {
				path := filepath.Join(dir, masterKeyFile)
				moved := filepath.Join(t.TempDir(), "master.key")
				if err := os.Rename(path, moved); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(moved, path); err != nil {
					t.Fatal(err)
				}
			},
			want: "<dir>/master.key is a symbolic link",
		},
		{
			name: "master key is a directory",
			setup: func(t *testing.T, dir string) {
				path := filepath.Join(dir, masterKeyFile)
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			},
			want: "<dir>/master.key is not a regular file",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, dir, _ := openStore(t)
			s.Close()
			tt.setup(t, dir)
			_, _, err := reopen(t, dir, Options{})
			wantErr(t, err, nil, strings.ReplaceAll(tt.want, "<dir>", dir))
		})
	}
}

// TestOpenRefusesUnsafeDatabaseFiles plants a symbolic link or a file open to the group at each
// of SQLite's files: Open refuses it before SQLite opens anything, so neither the planted file nor
// a link's target changes.
func TestOpenRefusesUnsafeDatabaseFiles(t *testing.T) {
	for _, name := range []string{dbFile, dbFile + "-wal", dbFile + "-shm", dbFile + "-journal"} {
		t.Run(name+" is a symbolic link", func(t *testing.T) {
			s, dir, _ := openStore(t)
			s.Close()
			path := filepath.Join(dir, name)
			target := filepath.Join(t.TempDir(), name)
			if name == dbFile {
				if err := os.Rename(path, target); err != nil {
					t.Fatal(err)
				}
			} else {
				writePrivate(t, target, "planted")
			}
			content := readFile(t, target)
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
			_, _, err := reopen(t, dir, Options{})
			wantErr(t, err, nil, path+" is a symbolic link; ghgw refuses to follow links in its state")
			if !bytes.Equal(readFile(t, target), content) {
				t.Error("Open changed the link's target")
			}
		})
		t.Run(name+" is readable by the group", func(t *testing.T) {
			s, dir, _ := openStore(t)
			s.Close()
			path := filepath.Join(dir, name)
			if name != dbFile {
				writePrivate(t, path, "planted")
			}
			chmod(t, path, 0o640)
			content := readFile(t, path)
			_, _, err := reopen(t, dir, Options{})
			wantErr(t, err, nil, path+" is accessible by group or others (mode 0640); run chmod 600 "+path)
			if !bytes.Equal(readFile(t, path), content) {
				t.Error("Open changed the file")
			}
		})
	}
}

func TestOpenRefusesSymlinkedDirectory(t *testing.T) {
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "state")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	_, _, err := Open(context.Background(), link, Options{})
	wantErr(t, err, nil, link+" is a symbolic link")
}

func chmod(t *testing.T, path string, mode fs.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func TestMasterKey(t *testing.T) {
	otherKey := NewSecret(strings.TrimSpace(string(encodeMasterKey(bytes.Repeat([]byte{7}, masterKeyBytes)))))
	tests := []struct {
		name  string
		setup func(t *testing.T, dir string)
		opts  Options
		want  string
	}{
		{
			name: "another key in the key file",
			setup: func(t *testing.T, dir string) {
				writePrivate(t, filepath.Join(dir, masterKeyFile), otherKey.Reveal()+"\n")
			},
			want: "the master key in <dir>/master.key is not the key the database <dir>/ghgw.db was created with",
		},
		{
			name: "another key in GHGW_MASTER_KEY",
			opts: Options{MasterKey: otherKey},
			want: "the master key in GHGW_MASTER_KEY is not the key the database",
		},
		{
			name:  "key file removed",
			setup: func(t *testing.T, dir string) { remove(t, filepath.Join(dir, masterKeyFile)) },
			want:  "master key file <dir>/master.key is missing, but the database <dir>/ghgw.db was created with a master key; restore the file",
		},
		{
			name: "key file truncated",
			setup: func(t *testing.T, dir string) {
				writePrivate(t, filepath.Join(dir, masterKeyFile), otherKey.Reveal()[:20])
			},
			want: "master key file <dir>/master.key is malformed: want 32 bytes in standard base64, e.g. the output of: head -c 32 /dev/urandom | base64; restore it from a backup",
		},
		{
			name: "key file of 31 bytes",
			setup: func(t *testing.T, dir string) {
				writePrivate(t, filepath.Join(dir, masterKeyFile), string(encodeMasterKey(make([]byte, 31))))
			},
			want: "is malformed",
		},
		{
			name: "key file empty",
			setup: func(t *testing.T, dir string) {
				writePrivate(t, filepath.Join(dir, masterKeyFile), "")
			},
			want: "is malformed",
		},
		{
			name: "malformed GHGW_MASTER_KEY",
			opts: Options{MasterKey: NewSecret("not-a-key-but-a-secret-value-of-44-chars-!!")},
			want: "GHGW_MASTER_KEY is malformed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, dir, _ := openStore(t)
			s.Close()
			if tt.setup != nil {
				tt.setup(t, dir)
			}
			_, _, err := reopen(t, dir, tt.opts)
			wantErr(t, err, nil, strings.ReplaceAll(tt.want, "<dir>", dir))
			if err != nil && (strings.Contains(err.Error(), otherKey.Reveal()[:16]) || strings.Contains(err.Error(), "secret-value")) {
				t.Error("the error quotes the key")
			}
		})
	}
}

func writePrivate(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

func remove(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
}

func TestMasterKeyFromOptions(t *testing.T) {
	ctx := context.Background()
	key := NewSecret(strings.TrimSpace(string(encodeMasterKey(newMasterKey()))))
	dir := filepath.Join(t.TempDir(), "state")
	s, _, err := Open(ctx, dir, Options{MasterKey: key})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if err := s.AddOwner(ctx, "acme", NewSecret("github_pat_options"), time.Time{}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err := os.Lstat(filepath.Join(dir, masterKeyFile)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Open with a given master key wrote a key file (Lstat error = %v)", err)
	}

	// Surrounding white space, as in an environment file, is ignored.
	s, _, err = reopen(t, dir, Options{MasterKey: NewSecret(" " + key.Reveal() + "\n")})
	if err != nil {
		t.Fatalf("Open() with the same key error = %v", err)
	}
	if got, err := s.Credential(ctx, "acme"); err != nil || got.Reveal() != "github_pat_options" {
		t.Errorf("Credential() error = %v, or the credential differs", err)
	}
	s.Close()

	_, _, err = reopen(t, dir, Options{})
	wantErr(t, err, nil, "master.key is missing, but the database")
	if _, err := os.Lstat(filepath.Join(dir, masterKeyFile)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Open without a key created a key file for an existing database (Lstat error = %v)", err)
	}
}

func TestMalformedMasterKeyFileOnNewDatabase(t *testing.T) {
	// What an interrupted first start leaves: the key file is reported, never replaced.
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	writePrivate(t, filepath.Join(dir, masterKeyFile), "AAAA")
	_, _, err := reopen(t, dir, Options{})
	wantErr(t, err, nil, "master.key is malformed: want 32 bytes in standard base64, e.g. the output of: head -c 32 /dev/urandom | base64; nothing is sealed with it yet, so if a first start was interrupted, remove it and start again")
	if got := readFile(t, filepath.Join(dir, masterKeyFile)); string(got) != "AAAA" {
		t.Error("Open replaced the malformed master key file")
	}
}

func TestMasterKeyFileKeptOnNewDatabase(t *testing.T) {
	// A key file left from an earlier database (or written by the admin) is used, never replaced.
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	content := string(encodeMasterKey(newMasterKey()))
	writePrivate(t, filepath.Join(dir, masterKeyFile), content)
	if _, _, err := reopen(t, dir, Options{}); err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if got := readFile(t, filepath.Join(dir, masterKeyFile)); string(got) != content {
		t.Error("Open replaced the existing master key file")
	}
}

func TestLeftoverAdminTokenFile(t *testing.T) {
	// A token file without a token in the database is never adopted: it may be an earlier
	// database's token, already shared.
	s, dir, token := openStore(t)
	s.Close()
	remove(t, filepath.Join(dir, dbFile))
	for _, f := range []string{dbFile + "-wal", dbFile + "-shm"} {
		os.Remove(filepath.Join(dir, f))
	}
	_, _, err := reopen(t, dir, Options{})
	wantErr(t, err, nil, "admin token file "+dir+"/admin-token exists, but the database has no admin token (an interrupted first start or an earlier database left it); remove it and ghgw creates a new admin token")
	if got := readFile(t, filepath.Join(dir, adminTokenFile)); string(got) != token.Reveal()+"\n" {
		t.Error("Open changed the leftover admin token file")
	}

	remove(t, filepath.Join(dir, adminTokenFile))
	s, tokenPath, err := reopen(t, dir, Options{})
	if err != nil {
		t.Fatalf("Open() after removing the file error = %v", err)
	}
	if tokenPath == "" || readAdminToken(t, dir).Reveal() == token.Reveal() {
		t.Error("Open did not create a new admin token")
	}
	if err := s.AuthenticateAdmin(context.Background(), token); !errors.Is(err, ErrUnknownKey) {
		t.Errorf("AuthenticateAdmin(old token) error = %v, want ErrUnknownKey", err)
	}
}

func TestOwnersWithoutKeyCheck(t *testing.T) {
	ctx := context.Background()
	s, dir, _ := openStore(t)
	if err := s.AddOwner(ctx, "acme", NewSecret("github_pat_x"), timeZero); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("DELETE FROM meta WHERE key = 'key_check'"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	remove(t, filepath.Join(dir, masterKeyFile))
	_, _, err := reopen(t, dir, Options{})
	wantErr(t, err, nil, "the database "+dir+"/ghgw.db holds sealed credentials but no master key check; restore it from a backup")
	if _, err := os.Lstat(filepath.Join(dir, masterKeyFile)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Open created a master key for a damaged database (Lstat error = %v)", err)
	}
}

func TestAuthenticateAdmin(t *testing.T) {
	s, _, token := openStore(t)
	other, _ := newKey(adminTokenPrefix)
	tests := []struct {
		name  string
		token Secret
		ok    bool
	}{
		{name: "first token", token: token, ok: true},
		{name: "another well-formed token", token: other},
		{name: "empty", token: Secret{}},
		{name: "user key prefix", token: NewSecret("ghgw_" + strings.TrimPrefix(token.Reveal(), adminTokenPrefix))},
		{name: "upper case", token: NewSecret(strings.ToUpper(token.Reveal()))},
		{name: "trailing newline", token: NewSecret(token.Reveal() + "\n")},
		{name: "huge", token: NewSecret(token.Reveal() + strings.Repeat("a", 1<<20))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.AuthenticateAdmin(context.Background(), tt.token)
			if tt.ok {
				if err != nil {
					t.Errorf("AuthenticateAdmin() error = %v", err)
				}
				return
			}
			wantErr(t, err, ErrUnknownKey, "unknown admin token")
		})
	}
}

func TestMigrations(t *testing.T) {
	ms, err := migrations()
	if err != nil {
		t.Fatalf("migrations() error = %v", err)
	}
	if len(ms) == 0 {
		t.Fatal("no migration embedded")
	}

	tests := []struct {
		version int
		want    string
	}{
		{version: 999, want: "the database has schema version 999, but this ghgw knows only up to"},
		{version: -1, want: "the database has schema version -1, which no ghgw writes; restore it from a backup"},
	}
	for _, tt := range tests {
		t.Run(strconv.Itoa(tt.version), func(t *testing.T) {
			s, dir, _ := openStore(t)
			if _, err := s.db.Exec(fmt.Sprintf("PRAGMA user_version = %d", tt.version)); err != nil {
				t.Fatal(err)
			}
			before := schema(t, s.db)
			s.Close()
			_, _, err = reopen(t, dir, Options{})
			wantErr(t, err, nil, tt.want)

			db, err := sql.Open("sqlite", dsn(filepath.Join(dir, dbFile)))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var version int
			if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != tt.version {
				t.Errorf("user_version = %d (error %v), want it left at %d", version, err, tt.version)
			}
			if after := schema(t, db); after != before {
				t.Errorf("the refused Open changed the schema:\n%s\nwant:\n%s", after, before)
			}
		})
	}
}

// schema returns the database's schema as SQL.
func schema(t *testing.T, db *sql.DB) string {
	t.Helper()
	var text string
	if err := db.QueryRow("SELECT group_concat(sql, ';\n') FROM (SELECT sql FROM sqlite_schema ORDER BY name)").Scan(&text); err != nil {
		t.Fatal(err)
	}
	return text
}

func TestContextIsHonored(t *testing.T) {
	s, _, _ := openStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.CreateUser(ctx, "agent"); !errors.Is(err, context.Canceled) {
		t.Errorf("CreateUser(canceled context) error = %v, want context.Canceled", err)
	}
	if _, err := s.State(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("State(canceled context) error = %v, want context.Canceled", err)
	}
}

func TestOpenWithoutDirectory(t *testing.T) {
	_, _, err := Open(context.Background(), "", Options{})
	wantErr(t, err, nil, "no state directory given")
}

// TestConcurrentFirstStart opens a new state directory from several goroutines at once: one
// master key and one admin token come out, and every store uses them.
func TestConcurrentFirstStart(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "state")
	const n = 8
	stores := make([]*Store, n)
	tokenPaths := make([]string, n)
	errs := make([]error, n)
	done := make(chan struct{})
	for i := range n {
		go func() {
			defer func() { done <- struct{}{} }()
			stores[i], tokenPaths[i], errs[i] = Open(ctx, dir, Options{})
		}()
	}
	for range n {
		<-done
	}
	var created int
	for i := range n {
		if errs[i] != nil {
			t.Fatalf("Open() error = %v", errs[i])
		}
		t.Cleanup(func() { stores[i].Close() })
		if tokenPaths[i] != "" {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("%d Opens created an admin token, want exactly 1", created)
	}
	token := readAdminToken(t, dir)
	if err := stores[0].AddOwner(ctx, "acme", NewSecret("github_pat_concurrent"), timeZero); err != nil {
		t.Fatal(err)
	}
	for i, s := range stores {
		if err := s.AuthenticateAdmin(ctx, token); err != nil {
			t.Errorf("store %d: AuthenticateAdmin() error = %v", i, err)
		}
		if got, err := s.Credential(ctx, "acme"); err != nil || got.Reveal() != "github_pat_concurrent" {
			t.Errorf("store %d: Credential() error = %v, or the credential differs", i, err)
		}
	}
}

// The environment of a child process of TestCrossProcessFirstStart: the state directory to open
// and the child's index.
const (
	childDirEnv   = "GHGW_TEST_FIRST_START_DIR"
	childIndexEnv = "GHGW_TEST_FIRST_START_INDEX"
	childCount    = 4
)

func TestMain(m *testing.M) {
	if dir := os.Getenv(childDirEnv); dir != "" {
		if err := firstStartChild(dir, os.Getenv(childIndexEnv)); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// firstStartChild opens the store in dir once the start file next to dir exists, adds its own
// owner, and then opens every child's credential and authenticates the admin token. It prints
// whether its Open created the admin token.
func firstStartChild(dir, index string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	wait := func(done func() (bool, error)) error {
		for {
			if ok, err := done(); ok || err != nil {
				return err
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Millisecond):
			}
		}
	}
	err := wait(func() (bool, error) {
		_, err := os.Stat(filepath.Join(filepath.Dir(dir), "start"))
		return err == nil, nil
	})
	if err != nil {
		return err
	}
	s, tokenPath, err := Open(ctx, dir, Options{})
	if err != nil {
		return err
	}
	defer s.Close()
	if err := s.AddOwner(ctx, "owner"+index, NewSecret("github_pat_child"+index), timeZero); err != nil {
		return err
	}
	for i := range childCount {
		err := wait(func() (bool, error) {
			token, err := s.Credential(ctx, fmt.Sprintf("owner%d", i))
			switch {
			case errors.Is(err, ErrNotFound):
				return false, nil
			case err != nil:
				return false, err
			case token.Reveal() != fmt.Sprintf("github_pat_child%d", i):
				return false, fmt.Errorf("the credential of owner%d differs", i)
			}
			return true, nil
		})
		if err != nil {
			return err
		}
	}
	data, err := readPrivateFile(filepath.Join(dir, adminTokenFile))
	if err != nil {
		return err
	}
	if err := s.AuthenticateAdmin(ctx, NewSecret(strings.TrimSuffix(string(data), "\n"))); err != nil {
		return err
	}
	fmt.Println("created admin token:", tokenPath != "")
	return nil
}

// TestCrossProcessFirstStart starts several processes on one new state directory at once: one
// creates the admin token, and every one authenticates it and opens the credentials the others
// sealed, so they all use one master key.
func TestCrossProcessFirstStart(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "state")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmds := make([]*exec.Cmd, childCount)
	outs := make([]bytes.Buffer, childCount)
	for i := range childCount {
		cmds[i] = exec.CommandContext(ctx, os.Args[0], "-test.run=^$")
		cmds[i].Env = append(os.Environ(), childDirEnv+"="+dir, childIndexEnv+"="+strconv.Itoa(i))
		cmds[i].Stdout, cmds[i].Stderr = &outs[i], &outs[i]
		if err := cmds[i].Start(); err != nil {
			t.Fatal(err)
		}
	}
	writePrivate(t, filepath.Join(root, "start"), "")
	created := 0
	for i, cmd := range cmds {
		if err := cmd.Wait(); err != nil {
			t.Errorf("child %d: %v\n%s", i, err, outs[i].String())
			continue
		}
		if strings.Contains(outs[i].String(), "created admin token: true") {
			created++
		}
	}
	if t.Failed() {
		return
	}
	if created != 1 {
		t.Errorf("%d processes created an admin token, want exactly 1", created)
	}
}
