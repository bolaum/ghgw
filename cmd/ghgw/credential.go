package main

import (
	"github.com/bolaum/ghgw/internal/setup"
	"github.com/spf13/cobra"
)

func newCredentialCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "credential ACTION",
		Short: "git's credential helper for the gateway (git runs it)",
		Long: "git's credential helper for the gateway, which ghgw setup configures: for get, it gives\n" +
			"git the saved ghgw key when git asks for the saved gateway, and nothing for any other\n" +
			"host. store and erase do nothing: the key stays in the ghgw config.",
		Example: "  printf 'protocol=https\\nhost=ghgw.example\\n\\n' | ghgw credential get",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := configPath()
			if err != nil {
				return err
			}
			c, err := setup.LoadConfig(path)
			if err != nil {
				return err
			}
			return setup.Credential(args[0], cmd.InOrStdin(), cmd.OutOrStdout(), c)
		},
	}
}
