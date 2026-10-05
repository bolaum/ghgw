package main

import (
	"os"
	"testing"
)

// runAsGhgw makes the test binary run as ghgw, for the tests that run ghgw in another process:
// git runs it as its credential helper.
const runAsGhgw = "GHGW_TEST_RUN_MAIN"

func TestMain(m *testing.M) {
	if os.Getenv(runAsGhgw) == "1" {
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}
