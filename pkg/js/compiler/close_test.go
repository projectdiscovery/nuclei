package compiler_test

//nolint:depguard // No depguard rules are configured, so its default list allows only the standard library.
import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/js/compiler"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

// TestCloseWithoutConnection calls Close on clients that never connected.
// The script must keep running past the call.
func TestCloseWithoutConnection(t *testing.T) {
	t.Parallel()

	scripts := map[string]string{
		"ssh": `
			const ssh = require('nuclei/ssh');
			ExportAs('closed', new ssh.SSHClient().Close());
			true;
		`,
		"net": `
			const net = require('nuclei/net');
			new net.NetConn().Close();
			ExportAs('closed', true);
			true;
		`,
	}
	for name, script := range scripts {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			program, err := compiler.SourceAutoMode(script, false)
			if err != nil {
				t.Fatal(err)
			}

			opts := new(compiler.ExecuteOptions)
			opts.ExecutionId = t.Name()
			opts.Source = &script // ExportAs is defined only for sources that use it.
			opts.TimeoutVariants = types.NewTimeoutVariant(5)

			result, err := compiler.New().ExecuteWithOptions(t.Context(), program, compiler.NewExecuteArgs(), opts)
			if err != nil {
				t.Fatal(err)
			}

			if got := result["closed"]; got != "true" {
				t.Errorf(`result["closed"] = %v, want "true"`, got)
			}
		})
	}
}
