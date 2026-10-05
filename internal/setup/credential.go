package setup

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// maxCredentialInput bounds what git sends a credential helper: a few short lines.
const maxCredentialInput = 64 << 10

// Credential answers one call of git's credential helper protocol (gitcredentials(7)) for the
// gateway in c: get returns the key when git asks for the gateway itself, store and erase do
// nothing (the key lives in the config file), and any other action is ignored, as the protocol
// asks. git only calls the helper for the gateway's URL; the check keeps the key from any other
// host whatever git's configuration says.
func Credential(action string, in io.Reader, out io.Writer, c Config) error {
	attrs := map[string]string{}
	sc := bufio.NewScanner(io.LimitReader(in, maxCredentialInput))
	for sc.Scan() && sc.Text() != "" {
		if k, v, ok := strings.Cut(sc.Text(), "="); ok {
			attrs[k] = v
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("read git's credential request: %w", err)
	}
	if action != "get" || attrs["protocol"] != "https" || !strings.EqualFold(attrs["host"], strings.TrimPrefix(c.URL, "https://")) {
		return nil
	}
	// The gateway ignores the username (SPEC.md section 5.1).
	_, err := fmt.Fprintf(out, "username=ghgw\npassword=%s\n", c.Key.Reveal())
	return err
}
