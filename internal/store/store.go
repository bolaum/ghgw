// Package store keeps ghgw's state in its state directory: the SQLite database (users, groups,
// grants, owners and admin tokens), the master key and, for the admin API, the first admin token.
// GitHub credentials are sealed with AES-256-GCM under the master key; ghgw keys and admin tokens
// are stored as SHA-256 hashes. Every change is validated by building a core.Policy from the
// result, so the database always holds a valid policy.
package store

import (
	"cmp"
	"context"
	"crypto/cipher"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/bolaum/ghgw/internal/core"
	"modernc.org/sqlite" // also registers the "sqlite" driver
	sqlite3 "modernc.org/sqlite/lib"
)

// Errors returned by the store wrap one of these, so transports can map them (404, 409, 400, 401).
var (
	ErrNotFound   = errors.New("not found")
	ErrExists     = errors.New("already exists")
	ErrInvalid    = errors.New("invalid")
	ErrUnknownKey = errors.New("unknown key")
)

// kindError is an error with its own message that still matches one of the errors above.
type kindError struct {
	kind error
	msg  string
}

func (e *kindError) Error() string { return e.msg }
func (e *kindError) Unwrap() error { return e.kind }

func errorf(kind error, format string, args ...any) error {
	return &kindError{kind: kind, msg: fmt.Sprintf(format, args...)}
}

// dbTimeout bounds every database call, whatever the caller's context allows. SQLite waits up to
// busyTimeout for a lock held by another connection. maxConns bounds the connections, so a flood
// of requests (unknown keys reach the database too) waits for one under its deadline instead of
// opening a file descriptor and a page cache each.
const (
	dbTimeout   = 10 * time.Second
	busyTimeout = 5 * time.Second
	maxConns    = 8
)

// Store is ghgw's state. It is safe for concurrent use.
type Store struct {
	db   *sql.DB
	aead cipher.AEAD
}

// Options configure Open.
type Options struct {
	// MasterKey is the master key in base64, from GHGW_MASTER_KEY. When it is zero, the key file
	// in the state directory is used, created on the first start.
	MasterKey Secret
	// AdminToken makes Open create the first admin token when the database has none, for the
	// admin API (SPEC.md section 9.2). The local admin commands have no use for one.
	AdminToken bool
}

// Open opens the store in the state directory dir. It refuses a directory or state file that is
// not private to the current user. On the first start it creates the directory, the database,
// the master key file (unless opts gives the key) and, with opts.AdminToken, the first admin
// token, all private to the current user; it never replaces an existing master key file. The
// master key must be the one the database was created with.
//
// adminTokenPath is the admin-token file when this call created the first admin token, for the
// caller to point the admin to; it is empty otherwise. The token itself is only in that file, so
// it never passes through the caller's output or logs.
func Open(ctx context.Context, dir string, opts Options) (_ *Store, adminTokenPath string, err error) {
	if dir == "" {
		return nil, "", errors.New("no state directory given")
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		return nil, "", err
	}
	if err := prepareDir(dir); err != nil {
		return nil, "", err
	}
	dbPath := filepath.Join(dir, dbFile)
	// SQLite would create the file with mode 0644; created here it is private from the start, and
	// SQLite gives its side files the same mode.
	if err := createPrivateFile(dbPath, nil); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, "", fmt.Errorf("create the database: %w", err)
	}
	db, err := sql.Open("sqlite", dsn(dbPath))
	if err != nil {
		return nil, "", fmt.Errorf("open the database: %w", err)
	}
	defer func() {
		if err != nil {
			db.Close()
		}
	}()
	db.SetMaxOpenConns(maxConns)
	db.SetMaxIdleConns(maxConns)
	s := &Store{db: db}
	if err := s.enableWAL(ctx); err != nil {
		return nil, "", err
	}
	if err := s.migrate(ctx); err != nil {
		return nil, "", err
	}
	if err := s.initMasterKey(ctx, dir, opts.MasterKey); err != nil {
		return nil, "", err
	}
	if opts.AdminToken {
		if adminTokenPath, err = s.initAdminToken(ctx, dir); err != nil {
			return nil, "", err
		}
	}
	return s, adminTokenPath, nil
}

// dsn returns the SQLite URI of the database: mode=rw because Open created the file, foreign keys
// on, secure_delete so a deleted credential's ciphertext does not stay in a free page of the
// database file (the WAL keeps old page images until it is checkpointed, at the latest on Close),
// and write transactions that take the write lock at BEGIN, so concurrent writers wait for
// each other instead of failing on upgrade.
func dsn(dbPath string) string {
	q := url.Values{}
	q.Set("mode", "rw")
	q.Set("_txlock", "immediate")
	q["_pragma"] = []string{
		"busy_timeout(" + strconv.FormatInt(busyTimeout.Milliseconds(), 10) + ")",
		"foreign_keys(1)",
		"secure_delete(1)",
	}
	return (&url.URL{Scheme: "file", Path: dbPath, RawQuery: q.Encode()}).String()
}

// enableWAL puts the database in WAL mode, so readers do not wait for writers. The mode is stored
// in the file, so this changes something only on the first start. The switch needs the database to
// itself and SQLite does not wait for it, so it is retried while a concurrent start holds a lock.
func (s *Store) enableWAL(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()
	for {
		var mode string
		err := s.db.QueryRowContext(ctx, "PRAGMA journal_mode = WAL").Scan(&mode)
		var sqlErr *sqlite.Error
		switch {
		case err == nil && mode == "wal":
			return nil
		case err == nil:
			return fmt.Errorf("the database cannot use WAL mode (it uses %s); keep the state directory on a local file system", mode)
		case !errors.As(err, &sqlErr) || sqlErr.Code()&0xff != sqlite3.SQLITE_BUSY:
			return dbErr(err)
		}
		select {
		case <-ctx.Done():
			return dbErr(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

//go:embed migrations/*.sql
var migrationFiles embed.FS

var migrationNameRE = regexp.MustCompile(`^([0-9]{4})_[a-z0-9_]+\.sql$`)

type migration struct {
	name string
	sql  string
}

// migrations returns the embedded migrations in order. File n (1-based) must be numbered n, so a
// gap or a duplicate fails every start instead of skipping a migration.
func migrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		return nil, err
	}
	slices.SortFunc(entries, func(a, b fs.DirEntry) int { return cmp.Compare(a.Name(), b.Name()) })
	ms := make([]migration, 0, len(entries))
	for i, e := range entries {
		m := migrationNameRE.FindStringSubmatch(e.Name())
		if m == nil {
			return nil, fmt.Errorf("migration %s: want NNNN_name.sql", e.Name())
		}
		if n, _ := strconv.Atoi(m[1]); n != i+1 {
			return nil, fmt.Errorf("migration %s: want number %04d", e.Name(), i+1)
		}
		b, err := fs.ReadFile(migrationFiles, path.Join("migrations", e.Name()))
		if err != nil {
			return nil, err
		}
		ms = append(ms, migration{name: e.Name(), sql: string(b)})
	}
	return ms, nil
}

// migrate applies the migrations the database lacks, in one transaction. The database records how
// many it has in PRAGMA user_version.
func (s *Store) migrate(ctx context.Context) error {
	ms, err := migrations()
	if err != nil {
		return err
	}
	return s.write(ctx, func(ctx context.Context, tx *sql.Tx) error {
		var version int
		if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
			return fmt.Errorf("read the database version: %w", err)
		}
		switch {
		case version < 0:
			return fmt.Errorf("the database has schema version %d, which no ghgw writes; restore it from a backup", version)
		case version > len(ms):
			return fmt.Errorf("the database has schema version %d, but this ghgw knows only up to %d; run a newer ghgw", version, len(ms))
		}
		for i, m := range ms[version:] {
			if _, err := tx.ExecContext(ctx, m.sql); err != nil {
				return fmt.Errorf("apply migration %s: %w", m.name, err)
			}
			// PRAGMA takes no parameters; the version is an integer this code computed.
			if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", version+i+1)); err != nil {
				return fmt.Errorf("apply migration %s: %w", m.name, err)
			}
		}
		return nil
	})
}

// write runs fn in a write transaction, bounded by dbTimeout, and commits if fn succeeds.
func (s *Store) write(ctx context.Context, fn func(context.Context, *sql.Tx) error) error {
	return s.tx(ctx, nil, fn)
}

// read runs fn in a read-only transaction, bounded by dbTimeout, so it sees one consistent state.
func (s *Store) read(ctx context.Context, fn func(context.Context, *sql.Tx) error) error {
	return s.tx(ctx, &sql.TxOptions{ReadOnly: true}, fn)
}

func (s *Store) tx(ctx context.Context, opts *sql.TxOptions, fn func(context.Context, *sql.Tx) error) error {
	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, opts)
	if err != nil {
		return dbErr(err)
	}
	defer tx.Rollback()
	if err := fn(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return dbErr(err)
	}
	return nil
}

// change runs fn in a write transaction and commits only if the state it leaves is a valid
// policy: core is the one place that knows what a valid name, grant or owner is.
func (s *Store) change(ctx context.Context, fn func(context.Context, *sql.Tx) error) error {
	return s.write(ctx, func(ctx context.Context, tx *sql.Tx) error {
		if err := fn(ctx, tx); err != nil {
			return err
		}
		st, err := loadState(ctx, tx)
		if err != nil {
			return err
		}
		if _, err := core.NewPolicy(st, nil); err != nil {
			return errorf(ErrInvalid, "%s", strings.ReplaceAll(err.Error(), "\n", "; "))
		}
		return nil
	})
}

// exists reports whether query returns a row.
func exists(ctx context.Context, tx *sql.Tx, query string, args ...any) (bool, error) {
	var one int
	switch err := tx.QueryRowContext(ctx, query, args...).Scan(&one); {
	case errors.Is(err, sql.ErrNoRows):
		return false, nil
	case err != nil:
		return false, dbErr(err)
	}
	return true, nil
}

// affected returns an ErrNotFound error built from format and args when res changed no row.
func affected(res sql.Result, format string, args ...any) error {
	n, err := res.RowsAffected()
	if err != nil {
		return dbErr(err)
	}
	if n == 0 {
		return errorf(ErrNotFound, format, args...)
	}
	return nil
}

// maxNameLen bounds the user, group and owner names the store takes: no valid name is longer.
const maxNameLen = 100

// checkNameLen rejects a new name longer than any valid one before it reaches the database.
func checkNameLen(kind, name string) error {
	if len(name) > maxNameLen {
		return errorf(ErrInvalid, "%s name %s is longer than %d bytes", kind, core.Printable(name), maxNameLen)
	}
	return nil
}

// dbErr marks err as a database failure; it passes nil through.
func dbErr(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("database: %w", err)
}
