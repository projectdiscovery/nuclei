package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

const headerChildEnv = "NUCLEI_HEADER_CHILD_ARGS"

// -H values can contain "#", on the command line, in a header file and in the
// config file, while lines of a header file that start with "#" are skipped as
// comments.
func TestHeaderValuesKeepHash(t *testing.T) {
	if args := os.Getenv(headerChildEnv); args != "" {
		options = &types.Options{Logger: gologger.DefaultLogger}
		os.Args = append([]string{os.Args[0]}, strings.Split(args, "\n")...)
		readConfig()
		fmt.Printf("headers=%s\n", strings.Join(options.CustomHeaders, "|"))
		os.Exit(0)
	}

	root := t.TempDir()
	headerFile := filepath.Join(root, "headers.txt")
	require.NoError(t, os.WriteFile(headerFile, []byte("# auth headers\nX-Token: abc#def\nReferer: https://app.example.com/#/dashboard\n"), 0o600))
	configFile := filepath.Join(root, "config.yaml")
	require.NoError(t, os.WriteFile(configFile, []byte("header:\n  - \"X-Config: cfg#value\"\n"), 0o600))

	tests := []struct {
		name string
		args []string
		want string
	}{
		{"cli and header file", []string{"-H", "Cookie: sid=1; color=#ff0000", "-H", headerFile}, "Cookie: sid=1; color=#ff0000|X-Token: abc#def|Referer: https://app.example.com/#/dashboard"},
		{"config file", []string{"-config", configFile}, "X-Config: cfg#value"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempRoot := filepath.Join(t.TempDir(), "tmp")
			require.NoError(t, os.Mkdir(tempRoot, 0o700))

			args := append(tt.args, "-disable-update-check")
			cmd := exec.Command(os.Args[0], "-test.run=^TestHeaderValuesKeepHash$", "-test.count=1")
			cmd.Env = isolatedNucleiStorageEnv(root, tempRoot, headerChildEnv+"="+strings.Join(args, "\n"))
			output, err := cmd.CombinedOutput()
			require.NoError(t, err, string(output))
			require.Contains(t, string(output), "headers="+tt.want+"\n")
		})
	}
}
