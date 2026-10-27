//go:build linux || darwin

package code

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/projectdiscovery/gozero/confine"
	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/stretchr/testify/require"
)

func dockerSandboxOrSkip(t *testing.T) {
	t.Helper()
	c, err := confine.New(&confine.Policy{Backend: confine.BackendDocker})
	if err != nil {
		t.Skipf("docker-backed gozero confinement unavailable: %v", err)
	}
	require.NoError(t, c.Close())
}

func executeSandboxedRequest(t *testing.T, request *Request) output.InternalEvent {
	t.Helper()
	dockerSandboxOrSkip(t)

	options := testutils.DefaultOptions.Copy()
	options.EnableCodeTemplates = true
	options.DisableSandbox = false
	testutils.Init(options)
	t.Cleanup(func() { testutils.Cleanup(options) })

	info := &testutils.TemplateInfo{
		ID:   "code-gozero-sandbox",
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	}
	executerOpts := testutils.NewMockExecuterOptions(options, info)
	executerOpts.Verified = true
	require.NoError(t, request.Compile(executerOpts))

	var gotEvent output.InternalEvent
	ctxArgs := contextargs.NewWithInput(context.Background(), "")
	require.NoError(t, request.ExecuteWithResults(ctxArgs, nil, nil, func(event *output.InternalWrappedEvent) {
		gotEvent = event.InternalEvent
	}))
	return gotEvent
}

func TestCodeProtocolGozeroSandboxExecution(t *testing.T) {
	gotEvent := executeSandboxedRequest(t, &Request{
		Engine: []string{"sh"},
		Source: "echo gozero-sandbox-ok",
	})
	require.Equal(t, "gozero-sandbox-ok", gotEvent["response"])
}

func TestCodeProtocolConfinementPolicyIsHardened(t *testing.T) {
	request := &Request{
		Sandbox: &Sandbox{
			WorkingDir: "/tmp/ignored",
			Image:      "python:3.14",
		},
	}
	options := testutils.DefaultOptions.Copy()
	options.GetTimeouts().CodeExecutionTimeout = 3 * time.Second
	request.options = testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{})

	policy := request.confinementPolicy(confine.BackendDocker)
	require.Equal(t, confine.BackendDocker, policy.Backend)
	require.Equal(t, "python:3.14", policy.DockerImage)
	require.False(t, policy.AllowNetwork)
	require.False(t, policy.WritableRootfs)
	require.False(t, policy.AllowCapabilities)
	require.False(t, policy.AllowNewPrivileges)
	require.Empty(t, policy.DockerUser)
	require.Equal(t, 65534, policy.RunAsUID, "payload must run as a non-root uid")
	require.Equal(t, 65534, policy.RunAsGID, "payload must run as a non-root gid")
	require.Equal(t, 3*time.Second, policy.Timeout)
	require.Empty(t, policy.Workspace, "template working-dir must not become a host workspace")

	native := request.confinementPolicy(confine.BackendAuto)
	require.Equal(t, confine.BackendAuto, native.Backend)
	require.False(t, native.AllowNetwork)
	require.False(t, native.AllowCapabilities)
	require.Empty(t, native.Tmp, "no shared writable temp dir for the payload")
	require.Empty(t, native.ReadOnlyPaths, "no home path is exposed")
	require.Equal(t, 3*time.Second, native.Timeout)
}

// TestCodeProtocolNativeFallbackConfinesPayload forces the Docker-unreachable
// path and runs a real payload through the gozero native backend (Seatbelt or
// bubblewrap): it can write its workspace, and it can neither write the home
// directory, read files under it (such as ~/.ssh) nor reach the network.
func TestCodeProtocolNativeFallbackConfinesPayload(t *testing.T) {
	if c, err := confine.New(&confine.Policy{Backend: confine.BackendAuto}); err != nil {
		t.Skipf("native sandbox unavailable: %v", err)
	} else {
		require.NoError(t, c.Close())
	}
	prev := dockerUnavailable.Swap(true)
	t.Cleanup(func() { dockerUnavailable.Store(prev) })

	home, err := os.UserHomeDir()
	require.NoError(t, err)
	canaryDir, err := os.MkdirTemp(home, ".nuclei-native-canary-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(canaryDir) })
	secret := "NUCLEI_NATIVE_SECRET"
	require.NoError(t, os.WriteFile(filepath.Join(canaryDir, "secret"), []byte(secret), 0o600))
	homeWrite := filepath.Join(canaryDir, "written")

	options := testutils.DefaultOptions.Copy()
	options.EnableCodeTemplates = true
	options.DisableSandbox = false
	testutils.Init(options)
	t.Cleanup(func() { testutils.Cleanup(options) })
	request := &Request{
		Engine: []string{"sh"},
		Source: fmt.Sprintf(`echo ws > "$HOME/ws-file" && cat "$HOME/ws-file"
echo pwned > %[1]q 2>/dev/null; test -f %[1]q && echo HOME_WRITE_OK || echo HOME_WRITE_DENIED
cat %[2]q 2>/dev/null || echo HOME_READ_DENIED
ls %[3]q >/dev/null 2>&1 && echo SSH_READ_OK || echo SSH_READ_DENIED
(exec 3<>/dev/tcp/1.1.1.1/80) 2>/dev/null && echo NET_OK || echo NET_DENIED`, homeWrite, filepath.Join(canaryDir, "secret"), filepath.Join(home, ".ssh")),
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   "code-native-sandbox",
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	executerOpts.Verified = true
	require.NoError(t, request.Compile(executerOpts))

	var gotEvent output.InternalEvent
	require.NoError(t, request.ExecuteWithResults(contextargs.NewWithInput(context.Background(), ""), nil, nil, func(event *output.InternalWrappedEvent) {
		gotEvent = event.InternalEvent
	}))
	response, _ := gotEvent["response"].(string)
	require.Contains(t, response, "ws\n")
	require.Contains(t, response, "HOME_WRITE_DENIED")
	require.Contains(t, response, "HOME_READ_DENIED")
	require.Contains(t, response, "SSH_READ_DENIED")
	require.NotContains(t, response, secret)
	require.NoFileExists(t, homeWrite)
}

func TestCodeProtocolGozeroSandboxDeniesHostFileRead(t *testing.T) {
	secret := "NUCLEI_HOST_SECRET_DO_NOT_LEAK"
	hostFile := filepath.Join(t.TempDir(), "host-secret")
	require.NoError(t, os.WriteFile(hostFile, []byte(secret), 0o600))

	gotEvent := executeSandboxedRequest(t, &Request{
		Engine: []string{"sh"},
		Source: fmt.Sprintf("cat %q 2>/dev/null || true", hostFile),
	})

	response, _ := gotEvent["response"].(string)
	stderr, _ := gotEvent["stderr"].(string)
	require.NotContains(t, response+stderr, secret)
}

func TestCodeProtocolGozeroSandboxDeniesNetwork(t *testing.T) {
	gotEvent := executeSandboxedRequest(t, &Request{
		Engine: []string{"sh"},
		Source: "wget -q -T 5 -O - http://example.com >/dev/null 2>&1 && echo REACHED || echo BLOCKED",
	})
	require.Equal(t, "BLOCKED", gotEvent["response"])
}
