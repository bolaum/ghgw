package main

import (
	"encoding/json"

	"github.com/bolaum/ghgw/internal/setup"
	"github.com/spf13/cobra"
)

func newWhoamiCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "whoami",
		Short: "Show who your ghgw key belongs to and what it may do",
		Long: "Ask the gateway who the saved ghgw key belongs to: the user, its groups and its effective\n" +
			"grants. $" + urlEnv + " and $" + tokenEnv + " override the saved gateway and key.",
		Example: "  ghgw whoami\n" +
			"  ghgw whoami --json",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, _, err := clientConfig()
			if err != nil {
				return err
			}
			who, err := setup.Whoami(cmd.Context(), nil, c)
			if err != nil {
				return err
			}
			if asJSON {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(who)
			}
			return printWhoami(cmd.OutOrStdout(), c.URL, who)
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print as JSON")
	return cmd
}
