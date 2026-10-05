package store

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bolaum/ghgw/internal/core"
)

// TestConnectionsAreBounded floods the store with well-formed unknown keys, which reach the
// database: callers wait for one of maxConns connections instead of opening more.
func TestConnectionsAreBounded(t *testing.T) {
	ctx := context.Background()
	s, _, _ := openStore(t)
	key, err := s.CreateUser(ctx, "agent")
	if err != nil {
		t.Fatal(err)
	}

	// With every connection taken, a call waits until its deadline and authenticates nobody.
	conns := make([]*sql.Conn, maxConns)
	for i := range conns {
		if conns[i], err = s.db.Conn(ctx); err != nil {
			t.Fatal(err)
		}
	}
	short, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if u, err := s.AuthenticateUser(short, key); !errors.Is(err, context.DeadlineExceeded) || u != (core.User{}) {
		t.Errorf("AuthenticateUser() with every connection taken = %+v, %v; want no user and context.DeadlineExceeded", u, err)
	}
	if got := s.db.Stats().OpenConnections; got != maxConns {
		t.Errorf("%d open connections, want %d", got, maxConns)
	}
	for _, c := range conns {
		c.Close()
	}

	unknown := NewSecret("ghgw_" + strings.Repeat("0", 64))
	const callers = 20 * maxConns
	errs := make([]error, callers)
	var wg sync.WaitGroup
	for i := range callers {
		wg.Go(func() {
			var u core.User
			if u, errs[i] = s.AuthenticateUser(ctx, unknown); u != (core.User{}) {
				errs[i] = errors.New("authenticated " + u.Name)
			}
		})
	}
	wg.Wait()
	for i, err := range errs {
		if !errors.Is(err, ErrUnknownKey) {
			t.Fatalf("caller %d: AuthenticateUser(unknown key) error = %v, want ErrUnknownKey", i, err)
		}
	}
	if st := s.db.Stats(); st.MaxOpenConnections != maxConns || st.OpenConnections > maxConns {
		t.Errorf("connection stats = %+v, want at most %d connections", st, maxConns)
	}
}

// TestAuthenticationFailures checks that a database failure authenticates nobody and opens no
// credential.
func TestAuthenticationFailures(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	tests := []struct {
		name  string
		setup func(s *Store) context.Context
		kind  error
	}{
		{name: "closed database", setup: func(s *Store) context.Context { s.Close(); return context.Background() }},
		{name: "canceled context", setup: func(*Store) context.Context { return canceled }, kind: context.Canceled},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			s, _, admin := openStore(t)
			key, err := s.CreateUser(ctx, "agent")
			if err != nil {
				t.Fatal(err)
			}
			if err := s.AddOwner(ctx, "acme", NewSecret("github_pat_acme"), timeZero); err != nil {
				t.Fatal(err)
			}
			ctx = tt.setup(s)
			check := func(what string, err error, zero bool) {
				t.Helper()
				switch {
				case err == nil || errors.Is(err, ErrUnknownKey) || errors.Is(err, ErrNotFound):
					t.Errorf("%s error = %v, want a database error", what, err)
				case tt.kind != nil && !errors.Is(err, tt.kind):
					t.Errorf("%s error = %v, want %v", what, err, tt.kind)
				case !zero:
					t.Errorf("%s returned a value with its error", what)
				}
			}
			u, err := s.AuthenticateUser(ctx, key)
			check("AuthenticateUser()", err, u == core.User{})
			check("AuthenticateAdmin()", s.AuthenticateAdmin(ctx, admin), true)
			cred, err := s.Credential(ctx, "acme")
			check("Credential()", err, cred.IsZero())
		})
	}
}

// TestKeySelectorCollisions stores a hash that shares a key's selector but not the rest: only
// the exact hash authenticates.
func TestKeySelectorCollisions(t *testing.T) {
	ctx := context.Background()
	s, _, admin := openStore(t)
	collide := func(hash []byte) []byte {
		c := slices.Clone(hash)
		c[len(c)-1] ^= 1
		return c
	}
	countCandidates := func(query string, hash []byte) {
		t.Helper()
		rows, err := s.db.Query(query, selector(hash))
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		n := 0
		for rows.Next() {
			n++
		}
		if n != 2 {
			t.Fatalf("%d candidates share the selector, want 2", n)
		}
	}

	key, err := s.CreateUser(ctx, "agent")
	if err != nil {
		t.Fatal(err)
	}
	userHash, _ := hashKey(userKeyPrefix, key)
	if _, err := s.db.Exec("INSERT INTO users (name, key_hash) VALUES ('collision', ?)", collide(userHash)); err != nil {
		t.Fatal(err)
	}
	countCandidates(userByKeyQuery, userHash)
	if u, err := s.AuthenticateUser(ctx, key); err != nil || u.Name != "agent" {
		t.Errorf("AuthenticateUser() = %+v, %v; want agent", u, err)
	}
	if err := s.DeleteUser(ctx, "agent"); err != nil {
		t.Fatal(err)
	}
	if u, err := s.AuthenticateUser(ctx, key); !errors.Is(err, ErrUnknownKey) || u != (core.User{}) {
		t.Errorf("AuthenticateUser() with only the colliding hash = %+v, %v; want ErrUnknownKey", u, err)
	}

	adminHash, _ := hashKey(adminTokenPrefix, admin)
	if _, err := s.db.Exec("INSERT INTO admin_tokens (token_hash, created_at) VALUES (?, 0)", collide(adminHash)); err != nil {
		t.Fatal(err)
	}
	countCandidates(adminByTokenQuery, adminHash)
	if err := s.AuthenticateAdmin(ctx, admin); err != nil {
		t.Errorf("AuthenticateAdmin() error = %v", err)
	}
	if _, err := s.db.Exec("DELETE FROM admin_tokens WHERE token_hash = ?", adminHash); err != nil {
		t.Fatal(err)
	}
	if err := s.AuthenticateAdmin(ctx, admin); !errors.Is(err, ErrUnknownKey) {
		t.Errorf("AuthenticateAdmin() with only the colliding hash error = %v, want ErrUnknownKey", err)
	}
}

func TestKeyLookupsUseSelectorIndex(t *testing.T) {
	s, _, _ := openStore(t)
	for query, index := range map[string]string{
		userByKeyQuery:    "users_key_selector",
		adminByTokenQuery: "admin_tokens_selector",
	} {
		rows, err := s.db.Query("EXPLAIN QUERY PLAN "+query, make([]byte, selectorBytes))
		if err != nil {
			t.Fatal(err)
		}
		var plan []string
		for rows.Next() {
			var (
				id, parent, unused int
				detail             string
			)
			if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
				t.Fatal(err)
			}
			plan = append(plan, detail)
		}
		rows.Close()
		if len(plan) != 1 || !strings.Contains(plan[0], "USING INDEX "+index+" ") {
			t.Errorf("plan of %q = %q, want a search using %s", query, plan, index)
		}
	}
}
