package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/bolaum/ghgw/internal/setup"
	"github.com/bolaum/ghgw/pkg/api"
	"github.com/spf13/cobra"
)

func newSetupCmd() *cobra.Command {
	var global, asJSON bool
	cmd := &cobra.Command{
		Use:   "setup --global",
		Short: "Make git and gh on this account go through the gateway",
		Long: "Set up this account to reach GitHub through the gateway: check the key with the gateway,\n" +
			"save the gateway URL and the key in $XDG_CONFIG_HOME/ghgw/config.yaml (mode 0600), make\n" +
			"git rewrite GitHub's URLs to the gateway and get the key from ghgw credential, and log gh in\n" +
			"to the gateway. The gateway and the key come from $" + urlEnv + " and $" + tokenEnv + " the first\n" +
			"time, and from the saved config after that. Running it again changes only what is missing\n" +
			"and prints what it changed. v0 sets up the whole account only (--global).",
		Example: "  GHGW_URL=https://ghgw.example GHGW_TOKEN=ghgw_... ghgw setup --global\n" +
			"  ghgw setup --global --json",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !global {
				return errors.New("v0 sets up the whole account only: run ghgw setup --global")
			}
			c, path, err := clientConfig()
			if err != nil {
				return err
			}
			exe, err := os.Executable()
			if err != nil {
				return fmt.Errorf("cannot find the ghgw binary for git's credential helper: %w", err)
			}
			r, err := setup.Global(cmd.Context(), setup.Options{ConfigPath: path, Config: c, Executable: exe})
			// What was changed before a failure is printed too.
			if perr := printSetup(cmd.OutOrStdout(), c.URL, r, asJSON); err == nil {
				err = perr
			}
			return err
		},
	}
	cmd.Flags().BoolVar(&global, "global", false, "set up the user's account (required in v0)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print as JSON")
	return cmd
}

type setupJSON struct {
	Whoami  *api.Whoami  `json:"whoami"`
	Changes []changeJSON `json:"changes"`
	Notes   []string     `json:"notes"`
}

type changeJSON struct {
	What    string `json:"what"`
	Changed bool   `json:"changed"`
}

func printSetup(w io.Writer, gateway string, r setup.Result, asJSON bool) error {
	if asJSON {
		out := setupJSON{Changes: []changeJSON{}, Notes: r.Notes}
		if r.Whoami.User != "" {
			out.Whoami = &r.Whoami
		}
		if out.Notes == nil {
			out.Notes = []string{}
		}
		for _, c := range r.Changes {
			out.Changes = append(out.Changes, changeJSON{What: c.What, Changed: c.Changed})
		}
		return json.NewEncoder(w).Encode(out)
	}
	if r.Whoami.User == "" {
		return nil
	}
	if err := printWhoami(w, gateway, r.Whoami); err != nil {
		return err
	}
	if len(r.Changes) > 0 {
		fmt.Fprintln(w)
	}
	for _, c := range r.Changes {
		state := "unchanged"
		if c.Changed {
			state = "changed  "
		}
		fmt.Fprintf(w, "%s  %s\n", state, c.What)
	}
	for _, n := range r.Notes {
		fmt.Fprintf(w, "note: %s\n", n)
	}
	return nil
}
