// Package policyfile reads the policy file: the users with the hashes of their ghgw keys, the
// groups and the grants, in YAML (SPEC.md section 6). Owners and their credentials are not in it:
// they are in the store.
package policyfile

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/bolaum/ghgw/internal/core"
	"go.yaml.in/yaml/v3"
)

// MaxSize bounds the policy file; a policy far larger than any real one is a mistake.
const MaxSize = 1 << 20

// keyHashPrefix names the hash function, so the file says what its hashes are.
const keyHashPrefix = "sha256:"

// File is a valid policy file.
type File struct {
	// State holds the users, groups and grants. It has no owners: they come from the store.
	State core.State
	// KeyHashes maps each user to the SHA-256 hash of its ghgw key.
	KeyHashes map[string][]byte
}

// The file's YAML. The type names appear in decoding errors ("field acess not found in type
// policyfile.grant"), so they name what the admin wrote.
type (
	policy struct {
		Users  map[string]user  `yaml:"users"`
		Groups map[string]group `yaml:"groups"`
	}
	user struct {
		// KeyHash is a node, not a string: decoding a tagged value (!!int ghgw_...) into a string
		// fails with an error that quotes it.
		KeyHash  yaml.Node `yaml:"key_hash"`
		Disabled bool      `yaml:"disabled"`
		Groups   []string  `yaml:"groups"`
		Grants   []grant   `yaml:"grants"`
	}
	group struct {
		Grants []grant `yaml:"grants"`
	}
	grant struct {
		ID     int      `yaml:"id"`
		Repos  []string `yaml:"repos"`
		Access string   `yaml:"access"`
		Push   []string `yaml:"push"`
		API    string   `yaml:"api"`
	}
)

// Load reads the policy file at path. The file must be a regular file of at most MaxSize bytes
// that only its owner can write: whoever can write it can grant themselves access.
func Load(path string) (*File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read the policy file: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("read the policy file: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("policy file %s is not a regular file", path)
	}
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return nil, fmt.Errorf("policy file %s is writable by group or others (mode %04o), who could grant themselves access; run chmod go-w %s", path, perm, path)
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxSize+1))
	if err != nil {
		return nil, fmt.Errorf("read the policy file: %w", err)
	}
	if len(data) > MaxSize {
		return nil, fmt.Errorf("policy file %s is larger than %d bytes", path, MaxSize)
	}
	pf, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("policy file %s is invalid; fix it and run again:\n%w", path, err)
	}
	return pf, nil
}

// Parse parses and validates a policy file. The error lists every problem, one per line.
func Parse(data []byte) (*File, error) {
	var p policy
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	switch err := dec.Decode(&p); {
	case errors.Is(err, io.EOF):
		// An empty file is an empty policy, which denies everything.
	case err != nil:
		return nil, decodeErr(err)
	default:
		if err := dec.Decode(new(yaml.Node)); !errors.Is(err, io.EOF) {
			return nil, errors.New("the file holds more than one YAML document; keep the whole policy in one")
		}
	}

	var errs []error
	pf := &File{KeyHashes: make(map[string][]byte, len(p.Users))}
	// Groups are sorted, and so are users, so the state and the errors do not depend on map order.
	members := make(map[string][]string, len(p.Groups))
	for _, name := range slices.Sorted(maps.Keys(p.Groups)) {
		members[name] = []string{}
	}
	byHash := make(map[string]string, len(p.Users))
	for _, name := range slices.Sorted(maps.Keys(p.Users)) {
		u := p.Users[name]
		pf.State.Users = append(pf.State.Users, core.User{Name: name, Disabled: u.Disabled})
		hash, err := parseKeyHash(u.KeyHash)
		switch other, dup := byHash[string(hash)]; {
		case err != nil:
			errs = append(errs, fmt.Errorf("user %s: %w", core.Printable(name), err))
		case dup:
			errs = append(errs, fmt.Errorf("users %s and %s have the same key_hash; give each user its own key (ghgw key new)", core.Printable(other), core.Printable(name)))
		default:
			byHash[string(hash)] = name
			pf.KeyHashes[name] = hash
		}
		for _, g := range u.Groups {
			if _, ok := members[g]; !ok {
				errs = append(errs, fmt.Errorf("user %s: group %s is not defined; add it under groups", core.Printable(name), core.Printable(g)))
				continue
			}
			members[g] = append(members[g], name)
		}
		errs = appendGrants(&pf.State, errs, core.Holder{Kind: core.HolderUser, Name: name}, u.Grants)
	}
	for _, name := range slices.Sorted(maps.Keys(p.Groups)) {
		pf.State.Groups = append(pf.State.Groups, core.Group{Name: name, Members: members[name]})
		errs = appendGrants(&pf.State, errs, core.Holder{Kind: core.HolderGroup, Name: name}, p.Groups[name].Grants)
	}
	// core is the one place that knows what a valid name and grant are.
	if _, err := core.NewPolicy(pf.State, nil); err != nil {
		errs = append(errs, err)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return pf, nil
}

// appendGrants adds the grants of holder to st, and every problem of the ones that are invalid to
// errs, which it returns.
func appendGrants(st *core.State, errs []error, holder core.Holder, grants []grant) []error {
	for i, g := range grants {
		switch {
		case g.ID == 0:
			errs = append(errs, fmt.Errorf("%s: grant %d in the list has no id; give it one no other grant has had, since decisions cite it", holder, i+1))
		case g.ID < 0:
			errs = append(errs, fmt.Errorf("%s: grant %d in the list has id %d; give it a positive one no other grant has had", holder, i+1, g.ID))
		}
		cg, err := core.ParseGrant(g.ID, holder, g.Repos, core.Access(g.Access), g.Push, core.Preset(g.API))
		if err != nil {
			errs = append(errs, err)
		}
		if g.ID > 0 && err == nil {
			st.Grants = append(st.Grants, cg)
		}
	}
	return errs
}

// FormatKeyHash returns hash as the policy file writes it.
func FormatKeyHash(hash []byte) string {
	return keyHashPrefix + hex.EncodeToString(hash)
}

// parseKeyHash parses a key_hash. Its errors never quote the value: it may be a pasted secret.
func parseKeyHash(n yaml.Node) ([]byte, error) {
	s := n.Value
	if n.Kind == 0 || n.Kind == yaml.ScalarNode && (s == "" || n.ShortTag() == "!!null") {
		return nil, errors.New("no key_hash; create a key with ghgw key new and paste the key_hash it prints")
	}
	if n.Kind == yaml.ScalarNode && strings.HasPrefix(s, "ghgw_") {
		return nil, errors.New("key_hash holds a ghgw key, not its hash; that key is exposed in the file now, so create a new one with ghgw key new and paste only its key_hash")
	}
	hash, err := hex.DecodeString(strings.TrimPrefix(s, keyHashPrefix))
	if n.Kind != yaml.ScalarNode || n.ShortTag() != "!!str" || !strings.HasPrefix(s, keyHashPrefix) || err != nil || len(hash) != sha256.Size {
		return nil, errors.New("key_hash must be sha256: and 64 hex characters, as ghgw key new prints it")
	}
	return hash, nil
}

// pastedKey matches a ghgw key or admin token, which YAML errors may quote: "*ghgw_..." is
// reported as an unknown anchor, and a value that does not fit its field is quoted in full.
var pastedKey = regexp.MustCompile(`ghgwa?_[0-9A-Za-z]+`)

// decodeErr returns the problems of a YAML decoding error one per line, without the "yaml: "
// prefix that says nothing to the admin, and with any key they quote redacted.
func decodeErr(err error) error {
	msgs := []string{strings.TrimPrefix(err.Error(), "yaml: ")}
	var te *yaml.TypeError
	if errors.As(err, &te) {
		msgs = te.Errors
	}
	errs := make([]error, len(msgs))
	for i, m := range msgs {
		errs[i] = errors.New(pastedKey.ReplaceAllString(m, "[redacted]"))
	}
	return errors.Join(errs...)
}
