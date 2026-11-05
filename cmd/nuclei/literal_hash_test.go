package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/internal/runner"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

const hashLiteralChildEnv = "NUCLEI_HASH_LITERAL_CHILD_ARGS"

// CLI, file and config inputs should preserve hashes in values, but full-line
// hash comments in list files must remain ignored.
func TestLiteralFileSliceOptionsKeepHash(t *testing.T) {
	if args := os.Getenv(hashLiteralChildEnv); args != "" {
		options = &types.Options{Logger: gologger.DefaultLogger}
		require.NoError(t, runner.ConfigureOptions())
		os.Args = append([]string{os.Args[0]}, strings.Split(args, "\n")...)
		readConfig()
		fmt.Printf("queries=%s\n", strings.Join(options.UncoverQuery, "|"))
		fmt.Printf("errors=%s\n", strings.Join(options.TrackError, "|"))
		os.Exit(0)
	}

	root := t.TempDir()
	queriesFile := filepath.Join(root, "queries.txt")
	require.NoError(t, os.WriteFile(queriesFile, []byte("# query comment\nbody:\"#app\"\ntitle:C#\n"), 0o600))
	errorsFile := filepath.Join(root, "errors.txt")
	require.NoError(t, os.WriteFile(errorsFile, []byte("# error comment\nerror#marker\n"), 0o600))
	configFile := filepath.Join(root, "config.yaml")
	require.NoError(t, os.WriteFile(configFile, []byte("uncover-query:\n  - 'body:\"#app\"'\ntrack-error:\n  - 'error#marker'\n"), 0o600))

	tests := []struct {
		name    string
		args    []string
		queries string
		errors  string
	}{
		{
			name: "command line",
			args: []string{"-uq", "title:C#", "-te", "error#marker"},
			queries: "title:C#",
			errors:  "error#marker",
		},
		{
			name: "list files",
			args: []string{"-uq", queriesFile, "-te", errorsFile},
			queries: "body:\"#app\"|title:C#",
			errors:  "error#marker",
		},
		{
			name: "config file",
			args: []string{"-config", configFile},
			queries: "body:\"#app\"",
			errors:  "error#marker",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempRoot := filepath.Join(t.TempDir(), "tmp")
			require.NoError(t, os.Mkdir(tempRoot, 0o700))

			args := append(append([]string(nil), tt.args...), "-disable-update-check")
			cmd := exec.Command(os.Args[0], "-test.run=^TestLiteralFileSliceOptionsKeepHash$", "-test.count=1")
			cmd.Env = isolatedNucleiStorageEnv(root, tempRoot, hashLiteralChildEnv+"="+strings.Join(args, "\n"))
			output, err := cmd.CombinedOutput()
			require.NoError(t, err, string(output))
			require.Contains(t, string(output), "queries="+tt.queries+"\n")
			require.Contains(t, string(output), "errors="+tt.errors+"\n")
		})
	}
}

func TestNormalizeLiteralFileSliceValue(t *testing.T) {
	cases := map[string]string{
		"body:\"#app\"": "body:\"#app\"",
		"error#marker": "error#marker",
		"# comment": "",
		"  # comment  ": "",
		" title:C# ": "title:C#",
	}
	for input, want := range cases {
		if got := normalizeLiteralFileSliceValue(input); got != want {
			t.Errorf("normalizeLiteralFileSliceValue(%q) = %q, want %q", input, got, want)
		}
	}
}
