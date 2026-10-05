// Package setup is the client side of ghgw (SPEC.md section 10): the saved gateway URL and key,
// git's and gh's configuration for the gateway, git's credential helper and whoami.
package setup

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/bolaum/ghgw/internal/store"
	"go.yaml.in/yaml/v3"
)

// Config is what ghgw setup saves: the gateway and the user's ghgw key.
type Config struct {
	// URL is the gateway's base URL, as ParseURL returns it: https://host[:port].
	URL string
	Key store.Secret
}

// maxConfigSize bounds the config file; a real one is about 120 bytes.
const maxConfigSize = 64 << 10

// configFile is the config file's YAML.
type configFile struct {
	URL string `yaml:"url"`
	Key string `yaml:"key"`
}

// ParseURL checks the gateway's URL and returns it in the form git's configuration uses:
// https://host[:port], lowercase, without the default port. The gateway serves git and the API at
// the root of its host, so a URL with anything else is a mistake.
func ParseURL(s string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(s))
	// The URL is not quoted: a key pasted into it would end up in the error.
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", errors.New("the gateway URL must be https://HOST or https://HOST:PORT, with nothing else")
	}
	host := strings.ToLower(u.Host)
	if u.Port() == "443" {
		host = strings.ToLower(u.Hostname())
	}
	return "https://" + host, nil
}

// ParseKey checks a ghgw key. The error never quotes it.
func ParseKey(s string) (store.Secret, error) {
	key := store.NewSecret(strings.TrimSpace(s))
	if _, ok := store.HashUserKey(key); !ok {
		return store.Secret{}, errors.New("that is not a ghgw key (ghgw_ and 64 lowercase hex characters); use the key the admin gave you")
	}
	return key, nil
}

// LoadConfig reads the config file at path. It must be a regular file that only its owner can
// read: it holds the key.
func LoadConfig(path string) (Config, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return Config{}, fmt.Errorf("no gateway is set up (%s does not exist); run ghgw setup --global with GHGW_URL and GHGW_TOKEN", path)
	}
	if err != nil {
		return Config{}, fmt.Errorf("read the ghgw config: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return Config{}, fmt.Errorf("read the ghgw config: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return Config{}, fmt.Errorf("ghgw config %s is not a regular file", path)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return Config{}, fmt.Errorf("ghgw config %s holds your key and is open to group or others (mode %04o); run chmod 600 %s", path, perm, path)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxConfigSize+1))
	if err != nil {
		return Config{}, fmt.Errorf("read the ghgw config: %w", err)
	}
	// YAML errors can quote the file, which holds the key: say only where the file is.
	malformed := fmt.Errorf("ghgw config %s is malformed; run ghgw setup --global again with GHGW_URL and GHGW_TOKEN", path)
	var cf configFile
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if len(data) > maxConfigSize || dec.Decode(&cf) != nil {
		return Config{}, malformed
	}
	c := Config{}
	if c.URL, err = ParseURL(cf.URL); err != nil {
		return Config{}, malformed
	}
	if c.Key, err = ParseKey(cf.Key); err != nil {
		return Config{}, malformed
	}
	return c, nil
}

// saveConfig writes c to path, mode 0600, unless it already holds c. It reports whether it wrote.
func saveConfig(path string, c Config) (bool, error) {
	data, err := yaml.Marshal(configFile{URL: c.URL, Key: c.Key.Reveal()})
	if err != nil {
		return false, err
	}
	data = append([]byte("# Written by ghgw setup: the gateway and your ghgw key. Keep it private.\n"), data...)
	return writePrivate(path, data)
}

// writePrivate replaces the file at path with data, mode 0600, creating its directory (mode
// 0700) when needed, unless it already holds data with that mode. It reports whether it wrote.
// The file is written whole under another name first, so a reader never sees half of it.
func writePrivate(path string, data []byte) (bool, error) {
	if fi, err := os.Lstat(path); err == nil && fi.Mode().IsRegular() && fi.Mode().Perm() == 0o600 {
		if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, data) {
			return false, nil
		}
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false, err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return false, err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		f.Close()
		return false, err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return false, err
	}
	if err := f.Close(); err != nil {
		return false, err
	}
	return true, os.Rename(f.Name(), path)
}
