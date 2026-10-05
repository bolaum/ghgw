package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"time"
)

// initMasterKey loads the master key, or creates the key file on the first start, and checks it
// against the key check sealed in the database. The write transaction serializes concurrent first
// starts.
func (s *Store) initMasterKey(ctx context.Context, dir string, given Secret) error {
	return s.write(ctx, func(ctx context.Context, tx *sql.Tx) error {
		var check []byte
		err := tx.QueryRowContext(ctx, "SELECT value FROM meta WHERE key = 'key_check'").Scan(&check)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return dbErr(err)
		}
		if check == nil {
			// Every owner is added after the key check, so owners without one mean a damaged
			// database: a new key would not open their credentials.
			sealed, err := exists(ctx, tx, "SELECT 1 FROM owners LIMIT 1")
			if err != nil {
				return err
			}
			if sealed {
				return fmt.Errorf("the database %s holds sealed credentials but no master key check; restore it from a backup", filepath.Join(dir, dbFile))
			}
		}
		key, source, err := loadMasterKey(dir, given, check != nil)
		if err != nil {
			return err
		}
		aead, err := newAEAD(key)
		if err != nil {
			return err
		}
		if check == nil {
			check = aead.Seal(nil, nil, []byte(keyCheckPlaintext), []byte(keyCheckAAD))
			if _, err := tx.ExecContext(ctx, "INSERT INTO meta (key, value) VALUES ('key_check', ?)", check); err != nil {
				return dbErr(err)
			}
		} else if pt, err := aead.Open(nil, nil, check, []byte(keyCheckAAD)); err != nil || string(pt) != keyCheckPlaintext {
			return fmt.Errorf("the master key in %s is not the key the database %s was created with; restore the right key",
				source, filepath.Join(dir, dbFile))
		}
		s.aead = aead
		return nil
	})
}

// loadMasterKey returns the master key and where it came from: given, else the key file, which is
// created only while the database has no key check (initialized is false). A database that has
// one was sealed with an existing key, and a new key would only lock its credentials away.
func loadMasterKey(dir string, given Secret, initialized bool) ([]byte, string, error) {
	if !given.IsZero() {
		const source = "GHGW_MASTER_KEY"
		key, err := parseMasterKey(given.Reveal())
		if err != nil {
			return nil, "", fmt.Errorf("%s is malformed: %w", source, err)
		}
		return key, source, nil
	}
	path := filepath.Join(dir, masterKeyFile)
	data, err := readPrivateFile(path)
	switch {
	case err == nil:
		key, err := parseMasterKey(string(data))
		switch {
		case err != nil && initialized:
			return nil, "", fmt.Errorf("master key file %s is malformed: %w; restore it from a backup", path, err)
		case err != nil:
			return nil, "", fmt.Errorf("master key file %s is malformed: %w; nothing is sealed with it yet, so if a first start was interrupted, remove it and start again", path, err)
		}
		return key, path, nil
	case !errors.Is(err, fs.ErrNotExist):
		return nil, "", fmt.Errorf("read the master key: %w", err)
	case initialized:
		return nil, "", fmt.Errorf("master key file %s is missing, but the database %s was created with a master key; restore the file from a backup or set GHGW_MASTER_KEY",
			path, filepath.Join(dir, dbFile))
	}
	key := newMasterKey()
	if err := createPrivateFile(path, encodeMasterKey(key)); err != nil {
		return nil, "", fmt.Errorf("create the master key: %w", err)
	}
	return key, path, nil
}

// initAdminToken stores the first admin token when the database has none, and returns the path of
// the file that holds it then. The file is written first, so the stored token is always in it. An
// admin-token file that already exists then is not adopted: it was left by an interrupted first
// start or by an earlier database, whose token may have been shared, so the admin removes it and
// gets a new one.
func (s *Store) initAdminToken(ctx context.Context, dir string) (string, error) {
	var created string
	err := s.write(ctx, func(ctx context.Context, tx *sql.Tx) error {
		found, err := exists(ctx, tx, "SELECT 1 FROM admin_tokens LIMIT 1")
		if err != nil || found {
			return err
		}
		path := filepath.Join(dir, adminTokenFile)
		token, hash := newKey(adminTokenPrefix)
		switch err := createPrivateFile(path, []byte(token.Reveal()+"\n")); {
		case errors.Is(err, fs.ErrExist):
			return fmt.Errorf("admin token file %s exists, but the database has no admin token (an interrupted first start or an earlier database left it); remove it and ghgw creates a new admin token", path)
		case err != nil:
			return fmt.Errorf("create the admin token: %w", err)
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO admin_tokens (token_hash, created_at) VALUES (?, ?)", hash, time.Now().Unix()); err != nil {
			return dbErr(err)
		}
		created = path
		return nil
	})
	if err != nil {
		return "", err
	}
	return created, nil
}

// AuthenticateAdmin checks an admin token. It returns an ErrUnknownKey error when the token is not
// one of the stored admin tokens.
func (s *Store) AuthenticateAdmin(ctx context.Context, token Secret) error {
	hash, ok := hashKey(adminTokenPrefix, token)
	if !ok {
		return errorf(ErrUnknownKey, "unknown admin token")
	}
	var found bool
	err := s.read(ctx, func(ctx context.Context, tx *sql.Tx) error {
		hashes, err := hashesBySelector(ctx, tx, adminByTokenQuery, hash)
		found = matchHash(hash, hashes) >= 0
		return err
	})
	if err != nil {
		return err
	}
	if !found {
		return errorf(ErrUnknownKey, "unknown admin token")
	}
	return nil
}

// hashesBySelector returns the hashes query finds for the selector of hash.
func hashesBySelector(ctx context.Context, tx *sql.Tx, query string, hash []byte) ([][]byte, error) {
	rows, err := tx.QueryContext(ctx, query, selector(hash))
	if err != nil {
		return nil, dbErr(err)
	}
	defer rows.Close()
	var hashes [][]byte
	for rows.Next() {
		var h []byte
		if err := rows.Scan(&h); err != nil {
			return nil, dbErr(err)
		}
		hashes = append(hashes, h)
	}
	if err := rows.Err(); err != nil {
		return nil, dbErr(err)
	}
	return hashes, nil
}
