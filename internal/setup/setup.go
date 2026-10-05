package setup

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os/exec"
	"strings"

	"github.com/bolaum/ghgw/pkg/api"
)

// Change is one setting setup makes; Changed is false when it was already there.
type Change struct {
	What    string
	Changed bool
}

// Options is what Global configures.
type Options struct {
	// ConfigPath is ghgw's config file, where the gateway and the key are saved.
	ConfigPath string
	Config     Config
	// Executable is this ghgw binary, which git runs as its credential helper.
	Executable string
	// Transport is what whoami uses; nil for http.DefaultTransport.
	Transport http.RoundTripper
}

// Result is what Global did.
type Result struct {
	Whoami  api.Whoami
	Changes []Change
	// Notes say what was left out and what to do about it.
	Notes []string
}

// Global configures the user's account for the gateway (SPEC.md section 10): it checks the key with
// whoami, saves the gateway and the key, makes git rewrite GitHub's URLs to the gateway and ask
// ghgw credential for the key, and logs gh in to the gateway. Nothing is changed when the key or
// git's configuration is wrong; a change that is already there is left as it is.
func Global(ctx context.Context, o Options) (Result, error) {
	var r Result
	var err error
	if r.Whoami, err = Whoami(ctx, o.Transport, o.Config); err != nil {
		return r, err
	}
	git, err := newGitConfig()
	if err != nil {
		return r, err
	}
	base := o.Config.URL + "/"
	bases, err := git.insteadOfs(ctx)
	if err != nil {
		return r, err
	}
	if err := checkRewrites(bases, base); err != nil {
		return r, err
	}

	saved, err := saveConfig(o.ConfigPath, o.Config)
	if err != nil {
		return r, fmt.Errorf("save the ghgw config: %w", err)
	}
	r.Changes = append(r.Changes, Change{What: o.ConfigPath + " saves the gateway URL and your ghgw key (mode 0600)", Changed: saved})
	rewrites, err := git.setRewrites(ctx, bases, base)
	r.Changes = append(r.Changes, rewrites...)
	if err != nil {
		return r, err
	}
	helper, err := git.setHelper(ctx, o.Config.URL, HelperCommand(o.Executable))
	if err != nil {
		return r, err
	}
	r.Changes = append(r.Changes, helper)
	return r, setGH(&r, o.Config)
}

// setGH logs gh in to the gateway, or notes why not.
func setGH(r *Result, c Config) error {
	host := strings.TrimPrefix(c.URL, "https://")
	if _, err := exec.LookPath("gh"); err != nil {
		r.Notes = append(r.Notes, "gh is not installed: once it is, run ghgw setup --global again")
		return nil
	}
	if u, err := url.Parse(c.URL); err == nil && u.Port() != "" {
		// gh looks up a host's token, and matches remotes to hosts, by host name without the port.
		r.Notes = append(r.Notes, fmt.Sprintf("gh is not set up: gh ignores the port of %s, so it would never send your key; serve the gateway on port 443", c.URL))
		return nil
	}
	dir, err := GHConfigDir()
	if err != nil {
		return err
	}
	change, others, err := setGHHost(dir, host, r.Whoami.User, c.Key)
	if err != nil {
		return err
	}
	r.Changes = append(r.Changes, change)
	if len(others) > 0 {
		r.Notes = append(r.Notes, fmt.Sprintf("gh also knows %s, so gh api goes to github.com unless GH_HOST=%s is set", strings.Join(others, ", "), host))
	}
	return nil
}
