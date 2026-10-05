package setup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"time"
)

// githubPrefixes are the ways remote URLs name a repository on GitHub; git rewrites each to the
// gateway.
var githubPrefixes = []string{"https://github.com/", "git@github.com:", "ssh://git@github.com/"}

// gitTimeout bounds one git command; git config only reads and writes local files.
const gitTimeout = 30 * time.Second

// gitConfig runs git config on the user's global configuration.
type gitConfig struct {
	git string
}

func newGitConfig() (gitConfig, error) {
	git, err := exec.LookPath("git")
	if err != nil {
		return gitConfig{}, errors.New("git is not installed; install it, then run ghgw setup --global again")
	}
	return gitConfig{git: git}, nil
}

// run runs git config --global with args. A missing key is not an error: git exits with 1 for a
// get that finds nothing, and with 5 for an unset that finds nothing.
func (g gitConfig) run(ctx context.Context, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, gitTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, g.git, append([]string{"config", "--global"}, args...)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if ee, ok := errors.AsType[*exec.ExitError](err); ok && (ee.ExitCode() == 1 || ee.ExitCode() == 5) && stderr.Len() == 0 {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("git config --global %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

// insteadOfs returns the url.<base>.insteadOf values of the global configuration, by base.
func (g gitConfig) insteadOfs(ctx context.Context) (map[string][]string, error) {
	out, err := g.run(ctx, "-z", "--get-regexp", `^url\..*\.insteadof$`)
	if err != nil {
		return nil, err
	}
	bases := map[string][]string{}
	// With -z, each entry is the key, a newline, the value and a NUL.
	for entry := range strings.SplitSeq(strings.TrimSuffix(out, "\x00"), "\x00") {
		key, value, ok := strings.Cut(entry, "\n")
		if !ok {
			continue
		}
		base := strings.TrimSuffix(strings.TrimPrefix(key, "url."), ".insteadof")
		bases[base] = append(bases[base], value)
	}
	return bases, nil
}

// checkRewrites fails when the global configuration rewrites one of githubPrefixes to anything
// but base: git would then send some remotes elsewhere. It names the command that removes it.
func checkRewrites(bases map[string][]string, base string) error {
	for _, other := range slices.Sorted(maps.Keys(bases)) {
		for _, v := range bases[other] {
			if other != base && slices.Contains(githubPrefixes, v) {
				return fmt.Errorf("git already rewrites %s to %s; remove that with\n  git config --global --fixed-value --unset url.%s.insteadOf %s\nthen run ghgw setup --global again", v, other, other, v)
			}
		}
	}
	return nil
}

// setRewrites makes git rewrite githubPrefixes to base, adding only the missing ones.
func (g gitConfig) setRewrites(ctx context.Context, bases map[string][]string, base string) ([]Change, error) {
	var changes []Change
	for _, prefix := range githubPrefixes {
		c := Change{What: fmt.Sprintf("git config --global url.%s.insteadOf %s", base, prefix)}
		if !slices.Contains(bases[base], prefix) {
			if _, err := g.run(ctx, "--add", "url."+base+".insteadOf", prefix); err != nil {
				return changes, err
			}
			c.Changed = true
		}
		changes = append(changes, c)
	}
	return changes, nil
}

// setHelper makes helper git's only credential helper for the gateway at gateway: the empty value
// first drops the helpers configured for every URL, so none of them is asked for the key or told
// to store it.
func (g gitConfig) setHelper(ctx context.Context, gateway, helper string) (Change, error) {
	key := "credential." + gateway + ".helper"
	want := []string{"", helper}
	c := Change{What: fmt.Sprintf("git config --global %s %q, then %q", key, "", helper)}
	out, err := g.run(ctx, "-z", "--get-all", key)
	if err != nil {
		return c, err
	}
	if slices.Equal(strings.Split(out, "\x00"), append(want, "")) {
		return c, nil
	}
	if _, err := g.run(ctx, "--unset-all", key); err != nil {
		return c, err
	}
	for _, v := range want {
		if _, err := g.run(ctx, "--add", key, v); err != nil {
			return c, err
		}
	}
	c.Changed = true
	return c, nil
}

// HelperCommand is the credential helper git runs for executable: git runs a helper that starts
// with ! through the shell, adding the action ("get") after it.
func HelperCommand(executable string) string {
	return "!" + shellQuote(executable) + " credential"
}

var shellSafe = regexp.MustCompile(`^[A-Za-z0-9_./+-]+$`)

func shellQuote(s string) string {
	if shellSafe.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
