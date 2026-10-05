// Command ghgw is a GitHub gateway for coding agents. See SPEC.md.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := newRootCmd().ExecuteContext(ctx)
	stop()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ghgw: %v\n", err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "ghgw",
		Short: "GitHub gateway for coding agents",
		Long: "ghgw sits between coding agents and GitHub, holds the real credentials and\n" +
			"allows only what the policy grants.",
		// Errors are printed once by main, in the "ghgw: ..." form agents are told to read.
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	root.AddCommand(newVersionCmd())
	return root
}
