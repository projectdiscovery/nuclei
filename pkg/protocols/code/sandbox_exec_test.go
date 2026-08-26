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

	policy := request.confinementPolicy()
	require.Equal(t, confine.BackendDocker, policy.Backend)
	require.Equal(t, "python:3.14", policy.DockerImage)
	require.False(t, policy.AllowNetwork)
	require.True(t, policy.ReadonlyRootfs)
	require.True(t, policy.DropAllCapabilities)
	require.True(t, policy.NoNewPrivileges)
	require.Equal(t, 65534, policy.RunAsUID, "payload must run as a non-root uid")
	require.Equal(t, 65534, policy.RunAsGID, "payload must run as a non-root gid")
	require.Equal(t, 3*time.Second, policy.Timeout)
	require.Empty(t, policy.Workspace, "template working-dir must not become a host workspace")
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
