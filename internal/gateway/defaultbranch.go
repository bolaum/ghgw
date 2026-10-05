package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/bolaum/ghgw/internal/core"
	"github.com/bolaum/ghgw/internal/store"
)

// DefaultAPIURL is GitHub's REST API.
const DefaultAPIURL = "https://api.github.com"

const (
	// maxRepoAnswer bounds GitHub's description of a repository; real ones are a few KiB.
	maxRepoAnswer = 1 << 20
	// maxBranchCache bounds the default branches held at once.
	maxBranchCache = 4096
)

// branchCache holds the default branches looked up recently, by lowercased repository: GitHub's
// names are case-insensitive. Only answers are cached, not failures.
type branchCache struct {
	mu      sync.Mutex
	entries map[string]branchEntry
}

type branchEntry struct {
	branch  string
	expires time.Time
}

func (c *branchCache) get(key string, now time.Time) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok || !now.Before(e.expires) {
		return "", false
	}
	return e.branch, true
}

// put holds branch for key until expires. A full cache drops what expired, or everything.
func (c *branchCache) put(key, branch string, now, expires time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[string]branchEntry)
	}
	if len(c.entries) >= maxBranchCache {
		for k, e := range c.entries {
			if !now.Before(e.expires) {
				delete(c.entries, k)
			}
		}
	}
	if len(c.entries) >= maxBranchCache {
		clear(c.entries)
	}
	c.entries[key] = branchEntry{branch: branch, expires: expires}
}

// defaultBranch returns the default branch of repo, from the cache or from GitHub's REST API with
// the owner's credential. An error is the reason, for the agent, why the push cannot be checked:
// the caller fails closed.
func (g *Gateway) defaultBranch(ctx context.Context, repo core.Repo, token store.Secret) (string, error) {
	key := strings.ToLower(repo.String())
	if branch, ok := g.branches.get(key, time.Now()); ok {
		return branch, nil
	}
	ctx, cancel := context.WithTimeout(ctx, g.limits.lookup)
	defer cancel()
	target := *g.apiURL
	target.Path = "/repos/" + repo.String()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "ghgw")
	req.Header.Set("Authorization", "Bearer "+token.Reveal())

	name, owner := core.Printable(repo.String()), core.Printable(repo.Owner())
	log := g.log.With("repo", repo.String())
	// The transport follows no redirect: the credential goes to the API host only.
	resp, err := g.transport.RoundTrip(req)
	if err != nil {
		if isTimeout(err) {
			log.Warn("default branch lookup timed out")
			return "", fmt.Errorf("looking up the default branch of %s took too long, so the push cannot be checked; try again later", name)
		}
		log.Warn("cannot reach the API for the default branch", "error", transportFailure(err))
		return "", fmt.Errorf("cannot reach GitHub to look up the default branch of %s, so the push cannot be checked; try again later", name)
	}
	defer resp.Body.Close()
	status := fmt.Sprintf("%d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	switch {
	case resp.StatusCode == http.StatusOK:
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusForbidden && resp.Header.Get("X-RateLimit-Remaining") == "0":
		log.Warn("default branch lookup rate limited", "status", resp.StatusCode)
		return "", fmt.Errorf("GitHub's rate limit for the credential of owner %s is used up, so the push to %s cannot be checked; try again later", owner, name)
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		log.Warn("the API refused the owner's credential", "status", resp.StatusCode)
		return "", fmt.Errorf("GitHub refused the credential of owner %s for %s (%s) when ghgw looked up its default branch; ask the admin to check that it is valid (ghgw owner list) and can read %s", owner, name, status, name)
	case resp.StatusCode == http.StatusNotFound:
		return "", fmt.Errorf("GitHub has no repository %s that the credential of owner %s can read; check the name, or ask the admin to give the credential access to it", name, owner)
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		log.Warn("the API redirected the default branch lookup", "status", resp.StatusCode)
		return "", fmt.Errorf("GitHub redirected the request for %s, and ghgw does not follow redirects; if the repository was renamed or transferred, use its new name", name)
	default:
		log.Warn("default branch lookup failed", "status", resp.StatusCode)
		return "", fmt.Errorf("GitHub answered %s when ghgw looked up the default branch of %s, so the push cannot be checked; try again later", status, name)
	}
	var answer struct {
		DefaultBranch string `json:"default_branch"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxRepoAnswer)).Decode(&answer); err != nil || answer.DefaultBranch == "" {
		if isTimeout(err) {
			log.Warn("default branch lookup timed out")
			return "", fmt.Errorf("looking up the default branch of %s took too long, so the push cannot be checked; try again later", name)
		}
		log.Warn("the API did not give the default branch")
		return "", fmt.Errorf("GitHub did not say which branch of %s is the default, so the push cannot be checked; try again later", name)
	}
	// core checks the name: an invalid one denies the push. One too long for a ref is not held.
	if len(answer.DefaultBranch) <= core.MaxRefNameLen {
		now := time.Now()
		g.branches.put(key, answer.DefaultBranch, now, now.Add(g.limits.branchTTL))
	}
	return answer.DefaultBranch, nil
}
