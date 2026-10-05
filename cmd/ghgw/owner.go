package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/bolaum/ghgw/internal/core"
	"github.com/bolaum/ghgw/internal/store"
	"github.com/spf13/cobra"
)

const (
	defaultAPIURL = "https://api.github.com"
	// githubTimeout bounds the call that checks a token.
	githubTimeout = 15 * time.Second
	// expirySoon is how long before a credential expires owner list starts warning.
	expirySoon = 7 * 24 * time.Hour
	timeLayout = "2006-01-02 15:04 UTC"
)

func newOwnerCmd() *cobra.Command {
	var stateDir string
	cmd := &cobra.Command{
		Use:   "owner",
		Short: "Manage the GitHub owners and their credentials in the local store",
		Long: "Manage the GitHub users and organizations ghgw holds a credential for. Credentials are\n" +
			"sealed under the master key ($" + masterKeyEnv + ", else master.key in the state directory).\n" +
			"Run these commands as the user ghgw serve runs as.",
	}
	addStateDirFlag(cmd, &stateDir)
	cmd.AddCommand(newOwnerAddCmd(&stateDir), newOwnerListCmd(&stateDir), newOwnerRemoveCmd(&stateDir))
	return cmd
}

// ownerJSON is an owner in --json output. ExpiresAt is null when GitHub reported no expiry.
type ownerJSON struct {
	Name      string     `json:"name"`
	ExpiresAt *time.Time `json:"expires_at"`
	UpdatedAt time.Time  `json:"updated_at,omitzero"`
}

func newOwnerJSON(name string, expiresAt, updatedAt time.Time) ownerJSON {
	o := ownerJSON{Name: name, UpdatedAt: updatedAt}
	if !expiresAt.IsZero() {
		o.ExpiresAt = &expiresAt
	}
	return o
}

func newOwnerAddCmd(stateDir *string) *cobra.Command {
	var (
		tokenFile, apiURL string
		asJSON            bool
	)
	cmd := &cobra.Command{
		Use:   "add OWNER",
		Short: "Add the credential of a GitHub user or organization",
		Long: "Add the credential of a GitHub user or organization: a fine-grained personal access token\n" +
			"limited to the repositories agents may use. The token is read from stdin or --token-file,\n" +
			"never from an argument, and checked with GitHub before it is stored.",
		Example: "  ghgw owner add bolaum --token-file bolaum.pat\n" +
			"  pass show github/acme | ghgw owner add acme --json",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, owner := cmd.Context(), args[0]
			if err := core.CheckOwnerName(owner); err != nil {
				return err
			}
			token, err := readToken(cmd.InOrStdin(), tokenFile)
			if err != nil {
				return err
			}
			s, err := openStore(ctx, *stateDir)
			if err != nil {
				return err
			}
			defer s.Close()
			expiry, err := checkToken(ctx, apiURL, owner, token)
			if err != nil {
				return err
			}
			expiresAt, err := parseExpiry(expiry)
			if err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "ghgw: warning: %v\n", err)
			}
			err = s.AddOwner(ctx, owner, token, expiresAt)
			if errors.Is(err, store.ErrExists) {
				return fmt.Errorf("owner %s already has a credential; to replace it, run ghgw owner remove %s first", owner, owner)
			}
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			if asJSON {
				return json.NewEncoder(w).Encode(newOwnerJSON(owner, expiresAt, time.Time{}))
			}
			_, err = fmt.Fprintf(w, "added the credential of owner %s (expires: %s)\n", owner, describeExpiry(expiresAt, time.Now()))
			return err
		},
	}
	cmd.Flags().StringVar(&tokenFile, "token-file", "", "read the token from this file instead of stdin")
	cmd.Flags().StringVar(&apiURL, "api-url", defaultAPIURL, "GitHub API to check the token with")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print as JSON")
	return cmd
}

func newOwnerListCmd(stateDir *string) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the owners and when their credentials expire; never the credentials",
		Example: "  ghgw owner list\n" +
			"  ghgw owner list --json",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := openStore(cmd.Context(), *stateDir)
			if err != nil {
				return err
			}
			defer s.Close()
			owners, err := s.Owners(cmd.Context())
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			if asJSON {
				out := make([]ownerJSON, len(owners))
				for i, o := range owners {
					out[i] = newOwnerJSON(o.Name, o.ExpiresAt, o.UpdatedAt)
				}
				return json.NewEncoder(w).Encode(out)
			}
			if len(owners) == 0 {
				_, err := fmt.Fprintln(w, "no owners; add one with ghgw owner add OWNER")
				return err
			}
			tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "OWNER\tEXPIRES\tUPDATED")
			now := time.Now()
			for _, o := range owners {
				fmt.Fprintf(tw, "%s\t%s\t%s\n", o.Name, describeExpiry(o.ExpiresAt, now), o.UpdatedAt.Format(timeLayout))
			}
			return tw.Flush()
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print as JSON")
	return cmd
}

func newOwnerRemoveCmd(stateDir *string) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "remove OWNER",
		Short: "Remove an owner and its credential",
		Example: "  ghgw owner remove acme\n" +
			"  ghgw owner remove acme --json",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := openStore(cmd.Context(), *stateDir)
			if err != nil {
				return err
			}
			defer s.Close()
			err = s.DeleteOwner(cmd.Context(), args[0])
			if errors.Is(err, store.ErrNotFound) {
				return fmt.Errorf("%w; ghgw owner list shows the owners", err)
			}
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			if asJSON {
				return json.NewEncoder(w).Encode(struct {
					Name string `json:"name"`
				}{args[0]})
			}
			_, err = fmt.Fprintf(w, "removed the credential of owner %s\n", args[0])
			return err
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print as JSON")
	return cmd
}

// readToken reads a token from the file at path, or from stdin when path is empty. It refuses a
// terminal on stdin: nothing waits for input, and a typed token would stay in the scrollback.
func readToken(stdin io.Reader, path string) (store.Secret, error) {
	r, source := stdin, "stdin"
	if path != "" {
		f, err := os.Open(path)
		if err != nil {
			return store.Secret{}, fmt.Errorf("read the token: %w", err)
		}
		defer f.Close()
		r, source = f, path
	} else if f, ok := stdin.(*os.File); ok {
		if fi, err := f.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
			return store.Secret{}, errors.New("no token: pipe it on stdin or pass --token-file")
		}
	}
	// A token and some room for the line break; anything longer is rejected whole, not cut to fit.
	const maxInput = store.MaxTokenLen + 16
	data, err := io.ReadAll(io.LimitReader(r, maxInput+1))
	if err != nil {
		return store.Secret{}, fmt.Errorf("read the token from %s: %w", source, err)
	}
	if len(data) > maxInput {
		return store.Secret{}, fmt.Errorf("the token from %s is malformed: it is longer than %d characters", source, store.MaxTokenLen)
	}
	token := store.NewSecret(strings.TrimSpace(string(data)))
	if err := store.CheckToken(token); err != nil {
		return store.Secret{}, fmt.Errorf("the token from %s is malformed: %w", source, err)
	}
	return token, nil
}

// checkToken asks GitHub for the owner with token, so a token GitHub rejects or an owner it does
// not know never reaches the store. It returns the expiry GitHub reported for the token, as sent.
func checkToken(ctx context.Context, apiURL, owner string, token store.Secret) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, githubTimeout)
	defer cancel()
	u, err := url.JoinPath(apiURL, "users", owner)
	if err != nil {
		return "", fmt.Errorf("--api-url: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", fmt.Errorf("--api-url: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token.Reveal())
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	// No redirects: the token is only for apiURL.
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("cannot check the token with GitHub: %s; check --api-url and the network and try again", transportFailure(err))
	}
	defer resp.Body.Close()
	// What the server sends may be crafted: the status is printed from its code, not its reason
	// phrase, and its message without the token, so neither can show the token or terminal
	// escapes.
	status := strings.TrimSpace(fmt.Sprintf("%d %s", resp.StatusCode, http.StatusText(resp.StatusCode)))
	switch {
	case resp.StatusCode == http.StatusOK:
		return resp.Header.Get("Github-Authentication-Token-Expiration"), nil
	case resp.StatusCode == http.StatusUnauthorized:
		return "", errors.New("GitHub rejected the token; check that it was copied whole and has not expired or been revoked")
	case resp.StatusCode == http.StatusNotFound:
		return "", fmt.Errorf("GitHub has no user or organization %s; check the owner name", owner)
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return "", fmt.Errorf("GitHub answered %s to the token check, a redirect ghgw does not follow so that the token goes nowhere else; check --api-url", status)
	}
	var body struct {
		Message string `json:"message"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&body)
	if body.Message == "" {
		return "", fmt.Errorf("GitHub answered %s to the token check; try again later", status)
	}
	msg := strings.ReplaceAll(body.Message, token.Reveal(), "[redacted]")
	return "", fmt.Errorf("GitHub answered %s to the token check (%s); fix that and try again", status, core.Printable(msg))
}

// transportFailure says why a request got no usable answer. It never returns err's text: a
// response net/http cannot parse is quoted in it, and the server may have put the token there.
func transportFailure(err error) string {
	var dnsErr *net.DNSError
	var opErr *net.OpError
	var certErr *tls.CertificateVerificationError
	switch {
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded):
		return fmt.Sprintf("no answer within %s", githubTimeout)
	case errors.As(err, &dnsErr):
		return "the host name does not resolve"
	case errors.As(err, &opErr) && opErr.Op == "dial":
		return "the connection was refused or could not be made"
	case errors.As(err, &certErr):
		return "the server's TLS certificate is not trusted"
	}
	return "the connection failed or the answer is not valid HTTP"
}

// parseExpiry parses the token expiry GitHub reports ("2026-11-01 12:00:00 UTC" or with an
// offset, "+0200"). An expiry it cannot read is returned as zero with an error, since the token
// itself is fine; the error does not quote it, since the server may have put the token there.
func parseExpiry(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	for _, layout := range []string{"2006-01-02 15:04:05 -0700", "2006-01-02 15:04:05 MST"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, errors.New("GitHub reported a token expiry ghgw cannot read; ghgw owner list will show none")
}

// describeExpiry says when a credential expires, and warns when that is soon or past.
func describeExpiry(expiresAt, now time.Time) string {
	switch {
	case expiresAt.IsZero():
		return "never"
	case !expiresAt.After(now):
		return expiresAt.Format(timeLayout) + " (expired: remove it and add a new token)"
	case expiresAt.Sub(now) < expirySoon:
		return expiresAt.Format(timeLayout) + " (expires soon: remove it and add a new token)"
	}
	return expiresAt.Format(timeLayout)
}
