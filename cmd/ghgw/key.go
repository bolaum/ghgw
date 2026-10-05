package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/bolaum/ghgw/internal/policyfile"
	"github.com/bolaum/ghgw/internal/store"
	"github.com/spf13/cobra"
)

func newKeyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "key",
		Short: "Create ghgw keys for the users of the policy file",
	}
	cmd.AddCommand(newKeyNewCmd())
	return cmd
}

type keyJSON struct {
	Key     string `json:"key,omitempty"`
	KeyFile string `json:"key_file,omitempty"`
	KeyHash string `json:"key_hash"`
}

func newKeyNewCmd() *cobra.Command {
	var (
		keyFile string
		asJSON  bool
	)
	cmd := &cobra.Command{
		Use:   "new",
		Short: "Create a ghgw key and print the hash for the policy file",
		Long: "Create a ghgw key for a user. The key is shown once, or written to --key-file (mode 0600)\n" +
			"so it never passes through the terminal. Give the key to the agent and paste the\n" +
			"key_hash line under the user in the policy file; ghgw keeps only the hash.",
		Example: "  ghgw key new\n" +
			"  ghgw key new --key-file rpi01-agent.key\n" +
			"  ghgw key new --key-file rpi01-agent.key --json",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			key, hash := store.NewUserKey()
			out := keyJSON{KeyHash: policyfile.FormatKeyHash(hash), KeyFile: keyFile}
			if keyFile != "" {
				if err := writeKeyFile(keyFile, key); err != nil {
					return err
				}
			} else {
				out.Key = key.Reveal()
			}
			w := cmd.OutOrStdout()
			if asJSON {
				return json.NewEncoder(w).Encode(out)
			}
			if out.Key != "" {
				if _, err := fmt.Fprintf(w, "key: %s\n", out.Key); err != nil {
					return err
				}
			}
			_, err := fmt.Fprintf(w, "key_hash: %s\n", out.KeyHash)
			return err
		},
	}
	cmd.Flags().StringVar(&keyFile, "key-file", "", "write the key to this new file (mode 0600) instead of printing it")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print as JSON")
	return cmd
}

// writeKeyFile writes key to a new file at path, private from the start. It never replaces a
// file: that could be another user's key.
func writeKeyFile(path string, key store.Secret) (err error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("key file %s exists; ghgw never replaces a key file: remove it or choose another path", path)
	}
	if err != nil {
		return fmt.Errorf("write the key file: %w", err)
	}
	defer func() {
		if err != nil {
			os.Remove(path)
		}
	}()
	if _, err := f.WriteString(key.Reveal() + "\n"); err != nil {
		f.Close()
		return fmt.Errorf("write the key file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("write the key file: %w", err)
	}
	return nil
}
