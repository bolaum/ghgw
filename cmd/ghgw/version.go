package main

import (
	"encoding/json"
	"fmt"
	"runtime/debug"

	"github.com/spf13/cobra"
)

// Set at build time with -ldflags "-X main.version=... -X main.commit=... -X main.date=...".
// Whatever is left empty comes from the build info Go embeds, so `go install ...@vX` still
// reports something useful.
var (
	version string
	commit  string
	date    string
)

type versionInfo struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
}

// resolveVersion fills the fields ldflags left empty from bi (which may be nil), then from
// defaults.
func resolveVersion(ldflags versionInfo, bi *debug.BuildInfo) versionInfo {
	info := ldflags
	if bi != nil {
		if info.Version == "" && bi.Main.Version != "(devel)" {
			info.Version = bi.Main.Version
		}
		for _, s := range bi.Settings {
			switch {
			case s.Key == "vcs.revision" && info.Commit == "":
				info.Commit = s.Value
			case s.Key == "vcs.time" && info.Date == "":
				info.Date = s.Value
			}
		}
	}
	if info.Version == "" {
		info.Version = "dev"
	}
	if info.Commit == "" {
		info.Commit = "unknown"
	}
	if info.Date == "" {
		info.Date = "unknown"
	}
	return info
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
			bi, _ := debug.ReadBuildInfo()
			info := resolveVersion(versionInfo{Version: version, Commit: commit, Date: date}, bi)
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
