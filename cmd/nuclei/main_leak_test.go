package main_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/nuclei/v3/internal/runner"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/rs/xid"
	"github.com/stretchr/testify/require"
	"github.com/tarunKoyalwar/goleak"
)

const cliLeakTestChildEnv = "NUCLEI_CLI_LEAKTEST_CHILD"

var cliKnownLeaks = []goleak.Option{
	goleak.Pretty(),
	goleak.IgnoreAnyFunction("net/http.(*http2ClientConn).readLoop"),
	goleak.IgnoreAnyFunction("net/http.(*persistConn).readLoop"),
	goleak.IgnoreAnyFunction("net/http.(*persistConn).writeLoop"),
	goleak.IgnoreAnyContainingPkg("github.com/hashicorp/golang-lru/v2/expirable"),
	goleak.IgnoreAnyContainingPkg("github.com/syndtr/goleveldb"),
	goleak.IgnoreAnyContainingPkg("github.com/projectdiscovery/ratelimit"),
	goleak.IgnoreAnyFunction("github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate.StartActiveMemGuardian.func1"),
}

// TestCLIRunnerGoroutineLeak runs a minimal CLI-path nuclei scan via internal/runner
// and asserts no unexpected goroutine leaks remain after Close.
//
// The body runs in a child process so shared package state from other tests
// does not pollute goleak (same approach as lib/tests SDK leak coverage).
func TestCLIRunnerGoroutineLeak(t *testing.T) {
	if os.Getenv(cliLeakTestChildEnv) == "1" {
		runCLIRunnerLeakTest(t)
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestCLIRunnerGoroutineLeak$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), cliLeakTestChildEnv+"=1")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "CLI leak test child failed:\n%s", string(out))
}

func runCLIRunnerLeakTest(t *testing.T) {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	_ = os.Setenv("DISABLE_STDOUT", "true")
	t.Cleanup(func() { _ = os.Unsetenv("DISABLE_STDOUT") })
	config.DefaultConfig.DisableUpdateCheck()

	defer func() {
		time.Sleep(2 * time.Second)
		goleak.VerifyNone(t, cliKnownLeaks...)
	}()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok)
	templatePath := filepath.Join(filepath.Dir(thisFile), "testdata", "leaktest", "basic-http.yaml")

	options := getDefaultOptions()
	options.Targets = []string{server.URL}
	options.Templates = []string{templatePath}
	options.NoInteractsh = true
	options.DisableStdin = true
	options.BulkSize = 1
	options.TemplateThreads = 1
	options.PayloadConcurrency = 1
	options.ExecutionId = xid.New().String()

	runner.ParseOptions(options)

	nucleiRunner, err := runner.New(options)
	require.NoError(t, err)
	require.NotNil(t, nucleiRunner)
	defer nucleiRunner.Close()

	require.NoError(t, nucleiRunner.RunEnumeration())
}
