//go:build integration
// +build integration

package integration_test

import (
	"os"
	"path/filepath"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
)

var securityHardeningTestcases = []integrationCase{
	{Path: "protocols/javascript/fs-read-deny.yaml", TestCase: &javascriptFSReadDeny{}},
	{Path: "protocols/javascript/fs-read-deny-lfa.yaml", TestCase: &javascriptFSReadDenyWithLFA{}},
	{Path: "protocols/javascript/net-deny-excluded.yaml", TestCase: &javascriptNetDenyExcluded{}},
	{Path: "protocols/javascript/fs-read-allowed-paths.yaml", TestCase: &javascriptFSReadAllowedPaths{}},
}

func securityHardeningRunner(allowLFA bool) *testutils.Runner {
	return suite.runner.Clone(testutils.WithAllowLocalFileAccess(allowLFA))
}

func runSecurityTemplate(filePath string, allowLFA bool, debug bool, extra ...string) ([]string, error) {
	return securityHardeningRunner(allowLFA).TemplateResults(filePath, "127.0.0.1", debug, extra...)
}

type javascriptFSReadDeny struct{}

func (j *javascriptFSReadDeny) Execute(filePath string) error {
	results, err := runSecurityTemplate(filePath, false, debug)
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}

type javascriptFSReadDenyWithLFA struct{}

func (j *javascriptFSReadDenyWithLFA) Execute(filePath string) error {
	results, err := runSecurityTemplate(filePath, true, debug, "-allow-local-file-access")
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}

type javascriptNetDenyExcluded struct{}

func (j *javascriptNetDenyExcluded) Execute(filePath string) error {
	results, err := runSecurityTemplate(filePath, false, debug, "-eh", "203.0.113.10")
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}

type javascriptFSReadAllowedPaths struct{}

func (j *javascriptFSReadAllowedPaths) Execute(filePath string) error {
	grantedDir, err := os.MkdirTemp("", "nuclei-allowed-paths-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(grantedDir)

	secretPath := filepath.Join(grantedDir, "secret.txt")
	if err := os.WriteFile(secretPath, []byte("granted-secret"), 0o600); err != nil {
		return err
	}

	results, err := runSecurityTemplate(
		filePath,
		true,
		debug,
		"-allow-local-file-access",
		"-ap", grantedDir,
		"-var", "ReadPath="+secretPath,
	)
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}
