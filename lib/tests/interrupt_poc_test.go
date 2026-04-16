package sdk_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
)

func timevalDuration(tv syscall.Timeval) time.Duration {
	return time.Duration(tv.Sec)*time.Second + time.Duration(tv.Usec)*time.Microsecond
}

func processCPUTime() time.Duration {
	var ru syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	return timevalDuration(ru.Utime) + timevalDuration(ru.Stime)
}

// infiniteLoopTemplate is a realistic-looking HTTP server fingerprinter.
// The hidden bug: normalizeToken resets i=0 whenever it hits "-", so any
// Server header value containing "-" (e.g. "nginx/1.18.0-ubuntu") causes
// an infinite CPU-bound loop. The mock server is hardcoded via %s/%s.
const infiniteLoopTemplate = `id: http-server-version-detect

info:
  name: HTTP Server Version Detection
  author: mikhail5555
  severity: info

javascript:
  - code: |
      var net = require("nuclei/net");
      var conn = net.Open("tcp", Host + ":" + Port);
      conn.Send("GET / HTTP/1.1\r\nHost: " + Host + "\r\nConnection: close\r\n\r\n");
      var raw = conn.RecvString();

      function extractHeader(response, name) {
        var lines = response.split("\r\n");
        for (var i = 0; i < lines.length; i++) {
          if (lines[i].toLowerCase().indexOf(name.toLowerCase() + ":") === 0) {
            return lines[i].substring(name.length + 1).trim();
          }
        }
        return "";
      }

      // Normalize server token by stripping distro suffix after "-".
      // e.g. "nginx/1.18.0-ubuntu" -> "nginx/1.18.0"
      function normalizeToken(token) {
        var result = "";
        var i = 0;
        while (i < token.length) {
          if (token[i] === "-") {
            // Distro tag starts here — discard accumulated chars and
            // restart scan from position 0 to re-validate the prefix.
            result = "";
            i = 0;
            continue;
          }
          result += token[i];
          i++;
        }
        return result;
      }

      var server = extractHeader(raw, "Server");
      ExportAs("server", normalizeToken(server));
      ExportAs("raw_server", server);

    args:
      Host: "%s"
      Port: "%s"

    matchers:
      - type: dsl
        dsl:
          - "success == true"
`

// TestJSInterruptOnContextCancel is a proof-of-concept for the goja runtime
// interrupt fix. It runs a JS template containing a hidden CPU-bound infinite
// loop against a mock HTTP server. The mock server returns a Server header of
// "nginx/1.18.0-ubuntu" — the "-ubuntu" suffix is what triggers the loop in
// normalizeToken.
//
// Without the fix (runtime.Interrupt on ctx cancel), the JS goroutine spins
// forever and ExecuteCallbackWithCtx never returns. With the fix it terminates
// at the context deadline.
//
// Run with: go test -v -run TestJSInterruptOnContextCancel ./lib/tests/
func TestJSInterruptOnContextCancel(t *testing.T) {
	// Mock server — returns a realistic Server header that triggers the loop.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.18.0-ubuntu")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	require.NoError(t, err)

	// Write the template to a temp file with the mock server address baked in.
	tmpl, err := os.CreateTemp("", "nuclei-interrupt-poc-*.yaml")
	require.NoError(t, err)
	defer os.Remove(tmpl.Name())
	_, err = fmt.Fprintf(tmpl, infiniteLoopTemplate, u.Hostname(), u.Port())
	require.NoError(t, err)
	require.NoError(t, tmpl.Close())

	const jsTimeout = 1 * time.Second

	engine, err := nuclei.NewNucleiEngineCtx(t.Context(),
		nuclei.DisableUpdateCheck(),
		nuclei.WithSandboxOptions(false, false), // allow localhost connections
		nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{
			Templates: []string{tmpl.Name()},
		}),
		func(e *nuclei.NucleiEngine) error {
			e.Options().GetTimeouts().JsCompilerExecutionTimeout = jsTimeout
			return nil
		},
	)
	require.NoError(t, err)
	defer engine.Close()

	engine.LoadTargets([]string{srv.URL}, false)

	start := time.Now()
	if err := engine.ExecuteCallbackWithCtx(t.Context(), nil); err != nil {
		require.NoError(t, err, "expected execution to finish without error")
	}
	elapsed := time.Since(start)

	t.Logf("ExecuteCallbackWithCtx returned in %v (JS timeout was %v)", elapsed, jsTimeout)

	// Give goroutines a moment to finish any in-flight cleanup.
	time.Sleep(time.Second)

	// Capture all goroutine stacks and look for frames belonging to the goja
	// JS runtime. A zombie goroutine from the old code would still be spinning
	// inside goja's execution loop and show up here. With the interrupt fix,
	// RunProgram returns promptly on ctx cancel — no goja frames survive.
	buf := make([]byte, 256*1024)
	n := runtime.Stack(buf, true)
	stacks := string(buf[:n])

	zombieCount := strings.Count(stacks, "github.com/Mzack9999/goja")
	t.Logf("goroutine frames referencing goja after execution: %d", zombieCount)
	if zombieCount > 0 {
		t.Logf("zombie goroutine stacks:\n%s", stacks)
	}

	// Measure process CPU consumption over 2 seconds while the zombie (if any)
	// is running. A spinning goja goroutine consumes ~1 full CPU core — CPU
	// time accrued during the window will be close to the wall-clock duration.
	const measureWindow = 2 * time.Second
	cpuBefore := processCPUTime()
	time.Sleep(measureWindow)
	cpuAfter := processCPUTime()

	cpuConsumed := cpuAfter - cpuBefore
	coresUsed := float64(cpuConsumed) / float64(measureWindow)
	t.Logf("CPU consumed over %v idle window: %v → %.2f cores in use", measureWindow, cpuConsumed, coresUsed)

	require.Zero(t, zombieCount, "zombie JS runtime detected: goja goroutine still running after context cancel")
}
