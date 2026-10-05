package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/bolaum/ghgw/internal/policyfile"
	"github.com/bolaum/ghgw/internal/store"
	"github.com/spf13/cobra"
)

const (
	stateDirEnv  = "GHGW_STATE_DIR"
	policyEnv    = "GHGW_POLICY"
	masterKeyEnv = "GHGW_MASTER_KEY"
)

// defaultPath returns $env when it is set, else rel under the XDG base directory $xdgEnv, which
// defaults to xdgDefault under the home directory.
func defaultPath(env, xdgEnv, xdgDefault, rel string) (string, error) {
	if p := os.Getenv(env); p != "" {
		return p, nil
	}
	// The XDG base directory specification says to ignore relative paths.
	if base := os.Getenv(xdgEnv); filepath.IsAbs(base) {
		return filepath.Join(base, rel), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("no home directory to find %s in: %w; set %s", rel, err, env)
	}
	return filepath.Join(home, xdgDefault, rel), nil
}

func addStateDirFlag(cmd *cobra.Command, dir *string) {
	cmd.PersistentFlags().StringVar(dir, "state-dir", "", "state directory (default $"+stateDirEnv+", else $XDG_STATE_HOME/ghgw)")
}

func addPolicyFlag(cmd *cobra.Command, path *string) {
	cmd.Flags().StringVar(path, "policy", "", "policy file (default $"+policyEnv+", else $XDG_CONFIG_HOME/ghgw/policy.yaml)")
}

// openStore opens the store in dir, or in the default state directory when dir is empty, with
// the master key from the environment when it is set there.
func openStore(ctx context.Context, dir string) (*store.Store, error) {
	if dir == "" {
		var err error
		if dir, err = defaultPath(stateDirEnv, "XDG_STATE_HOME", ".local/state", "ghgw"); err != nil {
			return nil, err
		}
	}
	// No admin token: v0 has no admin API to use it (SPEC.md section 9).
	s, _, err := store.Open(ctx, dir, store.Options{MasterKey: store.NewSecret(os.Getenv(masterKeyEnv))})
	return s, err
}

// policyPath returns path, or the default policy file when path is empty.
func policyPath(path string) (string, error) {
	if path != "" {
		return path, nil
	}
	return defaultPath(policyEnv, "XDG_CONFIG_HOME", ".config", "ghgw/policy.yaml")
}

// policyErr adds what to do to an error about the policy file at path.
func policyErr(path string, err error) error {
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("policy file %s does not exist; write it (SPEC.md section 6) or point to it with --policy or $%s", path, policyEnv)
	}
	return err
}

// loadPolicy loads the policy file at path, or at the default path when path is empty.
func loadPolicy(path string) (*policyfile.File, error) {
	path, err := policyPath(path)
	if err != nil {
		return nil, err
	}
	pf, err := policyfile.Load(path)
	return pf, policyErr(path, err)
}
