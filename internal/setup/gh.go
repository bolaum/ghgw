package setup

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"strings"

	"github.com/bolaum/ghgw/internal/store"
	"go.yaml.in/yaml/v3"
)

// GHConfigDir returns gh's configuration directory, found as gh finds it.
func GHConfigDir() (string, error) {
	if dir := os.Getenv("GH_CONFIG_DIR"); dir != "" {
		return dir, nil
	}
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return filepath.Join(dir, "gh"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("no home directory to find gh's configuration in: %w; set GH_CONFIG_DIR", err)
	}
	return filepath.Join(home, ".config", "gh"), nil
}

// ghHost is a host in gh's hosts.yml, as gh writes it after gh auth login --insecure-storage.
type ghHost struct {
	Users       map[string]ghUser `yaml:"users"`
	GitProtocol string            `yaml:"git_protocol"`
	OAuthToken  string            `yaml:"oauth_token"`
	User        string            `yaml:"user"`
}

type ghUser struct {
	OAuthToken string `yaml:"oauth_token"`
}

// maxHostsSize bounds gh's hosts.yml; a few hosts take a few hundred bytes.
const maxHostsSize = 1 << 20

// setGHHost logs gh in to host as user with key, in the hosts.yml in dir, without the calls of
// gh auth login (the API root and GraphQL, which the gateway does not serve). The other hosts are
// kept; others returns their names, since gh's default host is then github.com.
func setGHHost(dir, host, user string, key store.Secret) (c Change, others []string, err error) {
	path := filepath.Join(dir, "hosts.yml")
	c = Change{What: fmt.Sprintf("gh: %s logs in to %s as %s with your ghgw key", path, host, user)}
	want := ghHost{
		Users:       map[string]ghUser{user: {OAuthToken: key.Reveal()}},
		GitProtocol: "https",
		OAuthToken:  key.Reveal(),
		User:        user,
	}
	// gh's own errors and YAML's can quote the file, which holds tokens: say only where it is.
	invalid := fmt.Errorf("gh's %s is not a YAML mapping of hosts; fix it (or move it away), then run ghgw setup --global again", path)
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return c, nil, fmt.Errorf("read gh's configuration: %w", err)
	}
	if len(data) > maxHostsSize {
		return c, nil, invalid
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return c, nil, invalid
	}
	if len(doc.Content) == 0 {
		// A new file, or one with comments only.
		doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}}
	}
	hosts := doc.Content[0]
	if doc.Kind != yaml.DocumentNode || hosts.Kind != yaml.MappingNode {
		return c, nil, invalid
	}
	var value yaml.Node
	if err := value.Encode(want); err != nil {
		return c, nil, err
	}
	found := false
	for i := 0; i+1 < len(hosts.Content); i += 2 {
		name := hosts.Content[i].Value
		if !strings.EqualFold(name, host) {
			others = append(others, name)
			continue
		}
		found = true
		var have ghHost
		if hosts.Content[i+1].Decode(&have) == nil && maps.Equal(have.Users, want.Users) &&
			have.GitProtocol == want.GitProtocol && have.OAuthToken == want.OAuthToken && have.User == want.User {
			return c, others, nil
		}
		hosts.Content[i+1] = &value
	}
	if !found {
		hosts.Content = append(hosts.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: host}, &value)
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(4)
	if err := enc.Encode(&doc); err != nil {
		return c, others, err
	}
	if c.Changed, err = writePrivate(path, buf.Bytes()); err != nil {
		return c, others, fmt.Errorf("write gh's configuration: %w", err)
	}
	return c, others, nil
}
