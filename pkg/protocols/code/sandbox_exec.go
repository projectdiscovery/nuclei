package code

import (
	"context"
	"errors"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gozero"
	"github.com/projectdiscovery/gozero/confine"
	gozerotypes "github.com/projectdiscovery/gozero/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/sandbox"
	"github.com/projectdiscovery/utils/errkit"
)

// ErrNoCodeSandbox is returned when code templates cannot run confined: Docker
// is not reachable and no native sandbox works on this host. It fails closed;
// the template never runs on the bare host unless the user passes -no-sandbox.
var ErrNoCodeSandbox = errkit.New(noCodeSandboxMessage)

const noCodeSandboxMessage = "code template sandbox unavailable: docker is not reachable and no native sandbox works on this host (bubblewrap on linux, sandbox-exec on macos); use -no-sandbox to run code templates without a sandbox"

// dockerUnavailable latches once Docker reports it cannot confine, so later
// executions go straight to the native sandbox instead of probing a dead
// daemon on every request.
var dockerUnavailable atomic.Bool

// noSandboxReported makes the fail-closed error visible once at error level:
// per-request execution errors are only logged as warnings, which the
// default log level hides.
var noSandboxReported atomic.Bool

// evalCode runs the code template confined. Docker is preferred because the
// payload then sees only the image, not the host filesystem. When Docker is
// not reachable, the gozero native backend of the OS runs it (bubblewrap on
// Linux, Seatbelt on macOS): fresh workspace, no network, scrubbed
// environment, and the home directories and runtime sockets are hidden. When
// neither works, it fails closed.
func (request *Request) evalCode(ctx context.Context, input *gozero.Source) (*gozerotypes.Result, error) {
	if request.options.Options.DisableSandbox {
		return request.gozero.Eval(ctx, request.src, input)
	}

	if !dockerUnavailable.Load() {
		result, err := request.gozero.EvalWithVirtualEnv(ctx, request.confinementPolicy(confine.BackendDocker), request.src, input)
		if err == nil || !errors.Is(err, confine.ErrConfinementUnavailable) {
			return result, err
		}
		if dockerUnavailable.CompareAndSwap(false, true) {
			gologger.Verbose().Msgf("docker sandbox unavailable for code templates, using native sandbox: %v", err)
		}
	}

	result, err := request.gozero.EvalWithVirtualEnv(ctx, request.confinementPolicy(confine.BackendAuto), request.src, input)
	if err != nil && errors.Is(err, confine.ErrConfinementUnavailable) {
		reason := err.Error()
		if runtime.GOOS == "linux" && sandbox.Enforced() {
			// Landlock forbids mount(2) in this process and its children, and
			// bubblewrap needs mounts to build the sandbox.
			reason += " (bubblewrap cannot run under the landlock process sandbox)"
		}
		if noSandboxReported.CompareAndSwap(false, true) {
			gologger.Error().Msgf("%s (%s)", noCodeSandboxMessage, reason)
		}
		return nil, errkit.Wrap(ErrNoCodeSandbox, reason)
	}
	return result, err
}

// confinementPolicy returns the hardened gozero policy for backend. The
// gozero defaults are the hardened setting: no network, all capabilities
// dropped, no-new-privileges, read-only rootfs, resource limits, hidden home
// directories and a scrubbed environment.
func (request *Request) confinementPolicy(backend confine.Backend) *confine.Policy {
	policy := confine.DefaultPolicy()
	policy.Backend = backend
	if backend == confine.BackendDocker {
		// Run the payload as the unprivileged nobody user (65534) inside the
		// container, so a kernel/runc container escape maps to an unprivileged
		// host uid rather than root. The native backends keep the caller's uid,
		// so the workspace stays owned by it.
		policy.RunAsUID = 65534
		policy.RunAsGID = 65534
		// NOTE(max-hardening): Docker+runc shares the host kernel, so this
		// closes the application-level escape surface (no shell injection, no
		// unconfined fallback, deny-by-default, non-root) but not a
		// kernel/runc 0-day escape. For hostile multi-tenant use, run the
		// daemon on a kernel-isolating runtime (gVisor runsc or Kata microVM).
		if request.Sandbox != nil && request.Sandbox.Image != "" {
			policy.DockerImage = request.Sandbox.Image
		}
	}
	if timeout := request.codeTimeout(); timeout > 0 {
		policy.Timeout = timeout
	}
	return &policy
}

func (request *Request) codeTimeout() time.Duration {
	if request.options == nil || request.options.Options == nil {
		return 0
	}
	return time.Duration(request.options.Options.GetTimeouts().CodeExecutionTimeout)
}
