package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/bolaum/ghgw/internal/core"
	"github.com/bolaum/ghgw/internal/setup"
	"github.com/bolaum/ghgw/pkg/api"
)

// The gateway and the key ghgw setup saves, the first time.
const (
	urlEnv   = "GHGW_URL"
	tokenEnv = "GHGW_TOKEN"
)

// clientConfig returns the gateway and the key from $GHGW_URL and $GHGW_TOKEN, each falling back
// to the saved config, and the config file's path.
func clientConfig() (setup.Config, string, error) {
	path, err := configPath()
	if err != nil {
		return setup.Config{}, "", err
	}
	envURL, envKey := os.Getenv(urlEnv), os.Getenv(tokenEnv)
	var c setup.Config
	if envURL == "" || envKey == "" {
		if c, err = setup.LoadConfig(path); err != nil {
			return setup.Config{}, "", err
		}
	}
	if envURL != "" {
		if c.URL, err = setup.ParseURL(envURL); err != nil {
			return setup.Config{}, "", fmt.Errorf("$%s: %w", urlEnv, err)
		}
	}
	if envKey != "" {
		if c.Key, err = setup.ParseKey(envKey); err != nil {
			return setup.Config{}, "", fmt.Errorf("$%s: %w", tokenEnv, err)
		}
	}
	return c, path, nil
}

// printWhoami prints who the key belongs to and its grants. Everything the gateway sent goes
// through core.Printable: a terminal must not run what a gateway wrote.
func printWhoami(w io.Writer, gateway string, who api.Whoami) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "user\t%s\n", core.Printable(who.User))
	fmt.Fprintf(tw, "gateway\t%s\n", gateway)
	fmt.Fprintf(tw, "groups\t%s\n", printableList(who.Groups, "none"))
	if err := tw.Flush(); err != nil {
		return err
	}
	if len(who.Grants) == 0 {
		_, err := fmt.Fprintln(w, "\nno grants: ask the admin for access to the repositories you need")
		return err
	}
	fmt.Fprintln(w)
	fmt.Fprintln(tw, "GRANT\tHOLDER\tREPOS\tACCESS\tPUSH\tAPI")
	for _, g := range who.Grants {
		fmt.Fprintf(tw, "%d\t%s %s\t%s\t%s\t%s\t%s\n", g.ID, core.Printable(g.Holder.Kind), core.Printable(g.Holder.Name),
			printableList(g.Repos, "-"), core.Printable(g.Access), printableList(g.Push, "-"), core.Printable(g.API))
	}
	return tw.Flush()
}

func printableList(items []string, none string) string {
	if len(items) == 0 {
		return none
	}
	out := make([]string, len(items))
	for i, s := range items {
		out[i] = core.Printable(s)
	}
	return strings.Join(out, ", ")
}
