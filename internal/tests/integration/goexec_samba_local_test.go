//go:build integration
// +build integration

package integration_test

import (
	"os"
	"testing"
)

// TestGoExecSambaLocal is a developer-only driver that runs the Samba NTLM
// integration case unconditionally on the local machine, bypassing the
// `javascriptDockerDisabled` (Linux-only) gate used by the main suite. Skipped
// unless RUN_GOEXEC_SAMBA_LOCAL=1 is set so it does not run in CI.
func TestGoExecSambaLocal(t *testing.T) {
	if os.Getenv("RUN_GOEXEC_SAMBA_LOCAL") != "1" {
		t.Skip("set RUN_GOEXEC_SAMBA_LOCAL=1 to run; requires docker + free host port 445")
	}
	c := &javascriptGoExecSambaNTLM{}
	if err := c.Execute("protocols/javascript/goexec-samba-ntlm.yaml"); err != nil {
		t.Fatalf("samba ntlm integration failed: %v", err)
	}
}
