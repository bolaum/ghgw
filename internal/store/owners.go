package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// MaxTokenLen bounds a GitHub credential. GitHub's tokens are far shorter; the bound only keeps
// what the store accepts small.
const MaxTokenLen = 1024

// Owner is a GitHub user or organization with a credential. It never holds the credential.
type Owner struct {
	Name string
	// ExpiresAt is when GitHub said the credential expires; zero when it reported no expiry.
	ExpiresAt time.Time
	// UpdatedAt is when the credential was added or last rotated.
	UpdatedAt time.Time
}

// AddOwner stores the credential of a new owner, sealed under the master key. expiresAt is the
// expiry GitHub reported for the token, or zero.
func (s *Store) AddOwner(ctx context.Context, name string, token Secret, expiresAt time.Time) error {
	if err := checkNameLen("owner", name); err != nil {
		return err
	}
	if err := checkToken(token); err != nil {
		return err
	}
	return s.change(ctx, func(ctx context.Context, tx *sql.Tx) error {
		if err := mustNotExist(ctx, tx, "SELECT 1 FROM owners WHERE name = ?", name,
			"owner %s already has a credential; rotate it instead", display(name)); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, "INSERT INTO owners (name, credential, expires_at, updated_at) VALUES (?, ?, ?, ?)",
			name, s.seal(name, token), unixOrNull(expiresAt), time.Now().Unix())
		return dbErr(err)
	})
}

// RotateOwner replaces the credential of an existing owner.
func (s *Store) RotateOwner(ctx context.Context, name string, token Secret, expiresAt time.Time) error {
	if err := checkToken(token); err != nil {
		return err
	}
	return s.change(ctx, func(ctx context.Context, tx *sql.Tx) error {
		// Sealed for the stored name, the one Credential opens with, whatever case name is in.
		var stored string
		err := tx.QueryRowContext(ctx, "SELECT name FROM owners WHERE name = ?", name).Scan(&stored)
		if errors.Is(err, sql.ErrNoRows) {
			return errorf(ErrNotFound, "owner %s has no credential; add it first", display(name))
		}
		if err != nil {
			return dbErr(err)
		}
		_, err = tx.ExecContext(ctx, "UPDATE owners SET credential = ?, expires_at = ?, updated_at = ? WHERE name = ?",
			s.seal(stored, token), unixOrNull(expiresAt), time.Now().Unix(), stored)
		return dbErr(err)
	})
}

// DeleteOwner deletes an owner and its credential.
func (s *Store) DeleteOwner(ctx context.Context, name string) error {
	return s.change(ctx, func(ctx context.Context, tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, "DELETE FROM owners WHERE name = ?", name)
		if err != nil {
			return dbErr(err)
		}
		return affected(res, "owner %s has no credential", display(name))
	})
}

// Owners lists the owners, without their credentials.
func (s *Store) Owners(ctx context.Context) ([]Owner, error) {
	var owners []Owner
	err := s.read(ctx, func(ctx context.Context, tx *sql.Tx) error {
		return query(ctx, tx, "SELECT name, expires_at, updated_at FROM owners ORDER BY name", func(rows *sql.Rows) error {
			var (
				o       Owner
				expires sql.NullInt64
				updated int64
			)
			if err := rows.Scan(&o.Name, &expires, &updated); err != nil {
				return err
			}
			if expires.Valid {
				o.ExpiresAt = time.Unix(expires.Int64, 0).UTC()
			}
			o.UpdatedAt = time.Unix(updated, 0).UTC()
			owners = append(owners, o)
			return nil
		})
	})
	return owners, err
}

// Credential returns the credential of an owner (matched case-insensitively), opened with the
// master key.
func (s *Store) Credential(ctx context.Context, owner string) (Secret, error) {
	var (
		name   string
		sealed []byte
	)
	err := s.read(ctx, func(ctx context.Context, tx *sql.Tx) error {
		err := tx.QueryRowContext(ctx, "SELECT name, credential FROM owners WHERE name = ?", owner).Scan(&name, &sealed)
		if errors.Is(err, sql.ErrNoRows) {
			return errorf(ErrNotFound, "ghgw has no credential for owner %s", display(owner))
		}
		return dbErr(err)
	})
	if err != nil {
		return Secret{}, err
	}
	token, err := s.aead.Open(nil, nil, sealed, credentialAAD(name))
	if err != nil {
		return Secret{}, fmt.Errorf("the credential of owner %s was not sealed for it under this master key; rotate it", name)
	}
	return NewSecret(string(token)), nil
}

func (s *Store) seal(owner string, token Secret) []byte {
	return s.aead.Seal(nil, nil, []byte(token.Reveal()), credentialAAD(owner))
}

// checkToken accepts 1 to MaxTokenLen visible ASCII characters: a token is sent in an HTTP header,
// where anything else could split it. The error never quotes the token.
func checkToken(token Secret) error {
	t := token.Reveal()
	if len(t) == 0 || len(t) > MaxTokenLen {
		return errorf(ErrInvalid, "the token must be 1 to %d characters long", MaxTokenLen)
	}
	for _, c := range []byte(t) {
		if c <= ' ' || c > '~' {
			return errorf(ErrInvalid, "the token must be visible ASCII characters, without spaces or line breaks")
		}
	}
	return nil
}

func unixOrNull(t time.Time) sql.NullInt64 {
	if t.IsZero() {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: t.Unix(), Valid: true}
}
