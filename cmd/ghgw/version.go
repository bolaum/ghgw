package main

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

// Set at build time with -ldflags "-X main.version=... -X main.commit=... -X main.date=...".
// The defaults are what `go run` and plain `go build` report.
var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

type versionInfo struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
}

func newVersionCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version, commit and build date",
		Example: "  ghgw version\n" +
			"  ghgw version --json",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			info := versionInfo{Version: version, Commit: commit, Date: date}
			out := cmd.OutOrStdout()
			if asJSON {
				return json.NewEncoder(out).Encode(info)
			}
			_, err := fmt.Fprintf(out, "ghgw %s (commit %s, built %s)\n", info.Version, info.Commit, info.Date)
			return err
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print as JSON")
	return cmd
}
