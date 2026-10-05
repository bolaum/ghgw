package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

// run runs ghgw with args and stdin, as main would.
func run(t *testing.T, stdin string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	var out, errOut bytes.Buffer
	cmd := newRootCmd()
	cmd.SetIn(strings.NewReader(stdin))
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs(args)
	err = cmd.Execute()
	return out.String(), errOut.String(), err
}

// testEnv isolates a test from the environment the commands read.
func testEnv(t *testing.T) (stateDir string) {
	t.Helper()
	for _, env := range []string{stateDirEnv, policyEnv, masterKeyEnv, "XDG_STATE_HOME", "XDG_CONFIG_HOME"} {
		t.Setenv(env, "")
	}
	return filepath.Join(t.TempDir(), "state")
}
