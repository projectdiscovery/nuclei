package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolinit"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

const processSandboxChildEnv = "NUCLEI_PROCESS_SANDBOX_CHILD"

// TestCLIProcessSandboxWiring checks that the CLI turns the process-wide
// sandbox on by default and that -no-sandbox turns it off. readConfig parses
// os.Args and touches config dirs, so it runs in an isolated child process.
func TestCLIProcessSandboxWiring(t *testing.T) {
	if os.Getenv(processSandboxChildEnv) == "1" {
		options = &types.Options{Logger: gologger.DefaultLogger}
		os.Args = append([]string{os.Args[0], "-disable-update-check"}, strings.Fields(os.Getenv("NUCLEI_TEST_ARGS"))...)
		readConfig()
		fmt.Printf("process-sandbox=%v\n", protocolinit.ProcessSandboxEnabled(options))
		os.Exit(0)
	}

	tests := []struct {
		args string
		want string
	}{
		{args: "", want: "process-sandbox=true"},
		{args: "-no-sandbox", want: "process-sandbox=false"},
	}
	for _, test := range tests {
		t.Run("args="+test.args, func(t *testing.T) {
			root := t.TempDir()
			tempRoot := filepath.Join(root, "tmp")
			if err := os.Mkdir(tempRoot, 0o700); err != nil {
				t.Fatalf("create temporary root: %v", err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestCLIProcessSandboxWiring$", "-test.count=1")
			cmd.Env = isolatedNucleiStorageEnv(root, tempRoot,
				processSandboxChildEnv+"=1",
				"NUCLEI_TEST_ARGS="+test.args,
			)
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("child failed: %v\n%s", err, output)
			}
			if !strings.Contains(string(output), test.want) {
				t.Fatalf("expected %q in child output:\n%s", test.want, output)
			}
		})
	}
}
