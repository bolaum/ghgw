package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/bolaum/ghgw/internal/core"
)

// MaxGrantPatterns bounds the repository patterns and the push patterns of a grant, so the stored
// policy (and every decision built from it) stays small whatever the admin sends. core bounds the
// length of each pattern.
const MaxGrantPatterns = 100

// CreateUser creates an enabled user and returns its ghgw key. The key is not stored, only its
// hash: this is the only time it is available.
func (s *Store) CreateUser(ctx context.Context, name string) (Secret, error) {
	if err := checkNameLen("user", name); err != nil {
		return Secret{}, err
	}
	key, hash := newKey(userKeyPrefix)
	err := s.change(ctx, func(ctx context.Context, tx *sql.Tx) error {
		if err := mustNotExist(ctx, tx, "SELECT 1 FROM users WHERE name = ?", name, "user %s already exists", display(name)); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, "INSERT INTO users (name, key_hash) VALUES (?, ?)", name, hash)
		return dbErr(err)
	})
	if err != nil {
		return Secret{}, err
	}
	return key, nil
}

// RotateUserKey gives a user a new ghgw key and returns it; the old key stops working.
func (s *Store) RotateUserKey(ctx context.Context, name string) (Secret, error) {
	key, hash := newKey(userKeyPrefix)
	err := s.change(ctx, func(ctx context.Context, tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, "UPDATE users SET key_hash = ? WHERE name = ?", hash, name)
		if err != nil {
			return dbErr(err)
		}
		return affected(res, "user %s does not exist", display(name))
	})
	if err != nil {
		return Secret{}, err
	}
	return key, nil
}

// SetUserDisabled disables or enables a user. A disabled user is denied everything.
func (s *Store) SetUserDisabled(ctx context.Context, name string, disabled bool) error {
	return s.change(ctx, func(ctx context.Context, tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, "UPDATE users SET disabled = ? WHERE name = ?", disabled, name)
		if err != nil {
			return dbErr(err)
		}
		return affected(res, "user %s does not exist", display(name))
	})
}

// DeleteUser deletes a user with its key, its grants and its group memberships.
func (s *Store) DeleteUser(ctx context.Context, name string) error {
	return s.change(ctx, func(ctx context.Context, tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, "DELETE FROM users WHERE name = ?", name)
		if err != nil {
			return dbErr(err)
		}
		return affected(res, "user %s does not exist", display(name))
	})
}

// AuthenticateUser returns the user whose ghgw key is key, disabled or not: the policy denies
// disabled users with a reason. It returns an ErrUnknownKey error when no user has the key.
func (s *Store) AuthenticateUser(ctx context.Context, key Secret) (core.User, error) {
	hash, ok := hashKey(userKeyPrefix, key)
	if !ok {
		return core.User{}, errorf(ErrUnknownKey, "unknown ghgw key")
	}
	var (
		users  []core.User
		hashes [][]byte
	)
	err := s.read(ctx, func(ctx context.Context, tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, "SELECT name, disabled, key_hash FROM users WHERE substr(key_hash, 1, 8) = ?", selector(hash))
		if err != nil {
			return dbErr(err)
		}
		defer rows.Close()
		for rows.Next() {
			var (
				u core.User
				h []byte
			)
			if err := rows.Scan(&u.Name, &u.Disabled, &h); err != nil {
				return dbErr(err)
			}
			users, hashes = append(users, u), append(hashes, h)
		}
		return dbErr(rows.Err())
	})
	if err != nil {
		return core.User{}, err
	}
	i := matchHash(hash, hashes)
	if i < 0 {
		return core.User{}, errorf(ErrUnknownKey, "unknown ghgw key")
	}
	return users[i], nil
}

// CreateGroup creates an empty group.
func (s *Store) CreateGroup(ctx context.Context, name string) error {
	if err := checkNameLen("group", name); err != nil {
		return err
	}
	return s.change(ctx, func(ctx context.Context, tx *sql.Tx) error {
		if err := mustNotExist(ctx, tx, "SELECT 1 FROM groups WHERE name = ?", name, "group %s already exists", display(name)); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, "INSERT INTO groups (name) VALUES (?)", name)
		return dbErr(err)
	})
}

// DeleteGroup deletes a group with its grants and memberships; its members stay.
func (s *Store) DeleteGroup(ctx context.Context, name string) error {
	return s.change(ctx, func(ctx context.Context, tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, "DELETE FROM groups WHERE name = ?", name)
		if err != nil {
			return dbErr(err)
		}
		return affected(res, "group %s does not exist", display(name))
	})
}

// AddMember adds a user to a group. Adding a member twice is not an error.
func (s *Store) AddMember(ctx context.Context, group, user string) error {
	return s.change(ctx, func(ctx context.Context, tx *sql.Tx) error {
		if err := mustExist(ctx, tx, "SELECT 1 FROM groups WHERE name = ?", group, "group %s does not exist", display(group)); err != nil {
			return err
		}
		if err := mustExist(ctx, tx, "SELECT 1 FROM users WHERE name = ?", user, "user %s does not exist", display(user)); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO group_members (group_name, user_name) VALUES (?, ?)", group, user)
		return dbErr(err)
	})
}

// RemoveMember removes a user from a group.
func (s *Store) RemoveMember(ctx context.Context, group, user string) error {
	return s.change(ctx, func(ctx context.Context, tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, "DELETE FROM group_members WHERE group_name = ? AND user_name = ?", group, user)
		if err != nil {
			return dbErr(err)
		}
		return affected(res, "user %s is not a member of group %s", display(user), display(group))
	})
}

// AddGrant stores g and returns the ID it was given. g.ID must be zero: the store assigns IDs and
// never reuses one, since decisions and audit records cite them.
func (s *Store) AddGrant(ctx context.Context, g core.Grant) (int, error) {
	if g.ID != 0 {
		return 0, errorf(ErrInvalid, "a new grant has no ID; the store assigns one")
	}
	repos, err := patterns("repository", g.Repos)
	if err != nil {
		return 0, err
	}
	push, err := patterns("push", g.Push)
	if err != nil {
		return 0, err
	}
	var (
		user, group sql.NullString
		holder      = sql.NullString{String: g.Holder.Name, Valid: true}
		holderQuery string
	)
	switch g.Holder.Kind {
	case core.HolderUser:
		user, holderQuery = holder, "SELECT 1 FROM users WHERE name = ?"
	case core.HolderGroup:
		group, holderQuery = holder, "SELECT 1 FROM groups WHERE name = ?"
	default:
		return 0, errorf(ErrInvalid, "a grant belongs to a user or a group")
	}
	var id int
	err = s.change(ctx, func(ctx context.Context, tx *sql.Tx) error {
		if err := mustExist(ctx, tx, holderQuery, g.Holder.Name,
			"%s does not exist; create it first", g.Holder); err != nil {
			return err
		}
		err := tx.QueryRowContext(ctx,
			"INSERT INTO grants (user_name, group_name, repos, access, push, api) VALUES (?, ?, ?, ?, ?, ?) RETURNING id",
			user, group, repos, string(g.Access), push, string(g.API)).Scan(&id)
		return dbErr(err)
	})
	if err != nil {
		return 0, err
	}
	return id, nil
}

// patterns encodes a grant's patterns as a JSON array, within the limit.
func patterns[P fmt.Stringer](kind string, ps []P) (string, error) {
	if len(ps) > MaxGrantPatterns {
		return "", errorf(ErrInvalid, "a grant has at most %d %s patterns, not %d", MaxGrantPatterns, kind, len(ps))
	}
	texts := make([]string, len(ps))
	for i, p := range ps {
		texts[i] = p.String()
		if texts[i] == "" {
			return "", errorf(ErrInvalid, "%s pattern %d is empty", kind, i+1)
		}
	}
	b, err := json.Marshal(texts)
	return string(b), err
}

// DeleteGrant deletes a grant.
func (s *Store) DeleteGrant(ctx context.Context, id int) error {
	return s.change(ctx, func(ctx context.Context, tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, "DELETE FROM grants WHERE id = ?", id)
		if err != nil {
			return dbErr(err)
		}
		return affected(res, "grant %d does not exist", id)
	})
}

// State returns the stored policy, read in one transaction, for core.NewPolicy.
func (s *Store) State(ctx context.Context) (core.State, error) {
	var st core.State
	err := s.read(ctx, func(ctx context.Context, tx *sql.Tx) error {
		var err error
		st, err = loadState(ctx, tx)
		return err
	})
	return st, err
}

func loadState(ctx context.Context, tx *sql.Tx) (core.State, error) {
	var st core.State
	err := query(ctx, tx, "SELECT name, disabled FROM users ORDER BY name", func(rows *sql.Rows) error {
		var u core.User
		if err := rows.Scan(&u.Name, &u.Disabled); err != nil {
			return err
		}
		st.Users = append(st.Users, u)
		return nil
	})
	if err != nil {
		return core.State{}, err
	}
	err = query(ctx, tx, `SELECT g.name, m.user_name FROM groups g
		LEFT JOIN group_members m ON m.group_name = g.name ORDER BY g.name, m.user_name`, func(rows *sql.Rows) error {
		var (
			name   string
			member sql.NullString
		)
		if err := rows.Scan(&name, &member); err != nil {
			return err
		}
		if n := len(st.Groups); n == 0 || st.Groups[n-1].Name != name {
			st.Groups = append(st.Groups, core.Group{Name: name, Members: []string{}})
		}
		if member.Valid {
			g := &st.Groups[len(st.Groups)-1]
			g.Members = append(g.Members, member.String)
		}
		return nil
	})
	if err != nil {
		return core.State{}, err
	}
	err = query(ctx, tx, "SELECT id, user_name, group_name, repos, access, push, api FROM grants ORDER BY id", func(rows *sql.Rows) error {
		g, err := scanGrant(rows)
		if err != nil {
			return err
		}
		st.Grants = append(st.Grants, g)
		return nil
	})
	if err != nil {
		return core.State{}, err
	}
	err = query(ctx, tx, "SELECT name FROM owners ORDER BY name", func(rows *sql.Rows) error {
		var o string
		if err := rows.Scan(&o); err != nil {
			return err
		}
		st.Owners = append(st.Owners, o)
		return nil
	})
	if err != nil {
		return core.State{}, err
	}
	return st, nil
}

func scanGrant(rows *sql.Rows) (core.Grant, error) {
	var (
		g                        core.Grant
		user, group              sql.NullString
		repos, access, push, api string
	)
	if err := rows.Scan(&g.ID, &user, &group, &repos, &access, &push, &api); err != nil {
		return core.Grant{}, err
	}
	g.Holder = core.Holder{Kind: core.HolderUser, Name: user.String}
	if group.Valid {
		g.Holder = core.Holder{Kind: core.HolderGroup, Name: group.String}
	}
	g.Access, g.API = core.Access(access), core.Preset(api)
	var err error
	if g.Repos, err = parsePatterns(repos, core.ParseRepoGlob); err != nil {
		return core.Grant{}, fmt.Errorf("%s: %w", g, err)
	}
	if g.Push, err = parsePatterns(push, core.ParseBranchGlob); err != nil {
		return core.Grant{}, fmt.Errorf("%s: %w", g, err)
	}
	return g, nil
}

func parsePatterns[P any](text string, parse func(string) (P, error)) ([]P, error) {
	var texts []string
	if err := json.Unmarshal([]byte(text), &texts); err != nil {
		return nil, err
	}
	ps := make([]P, len(texts))
	for i, t := range texts {
		var err error
		if ps[i], err = parse(t); err != nil {
			return nil, err
		}
	}
	return ps, nil
}

// query runs q and calls scan for each row.
func query(ctx context.Context, tx *sql.Tx, q string, scan func(*sql.Rows) error) error {
	rows, err := tx.QueryContext(ctx, q)
	if err != nil {
		return dbErr(err)
	}
	defer rows.Close()
	for rows.Next() {
		if err := scan(rows); err != nil {
			return dbErr(err)
		}
	}
	return dbErr(rows.Err())
}

// mustNotExist returns an ErrExists error built from format and args when q with arg finds a row.
func mustNotExist(ctx context.Context, tx *sql.Tx, q string, arg any, format string, args ...any) error {
	found, err := exists(ctx, tx, q, arg)
	if err != nil {
		return err
	}
	if found {
		return errorf(ErrExists, format, args...)
	}
	return nil
}

// mustExist returns an ErrNotFound error built from format and args when q with arg finds no row.
func mustExist(ctx context.Context, tx *sql.Tx, q string, arg any, format string, args ...any) error {
	found, err := exists(ctx, tx, q, arg)
	if err != nil {
		return err
	}
	if !found {
		return errorf(ErrNotFound, format, args...)
	}
	return nil
}
