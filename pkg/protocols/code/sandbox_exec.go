package code

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gozero"
	"github.com/projectdiscovery/gozero/confine"
	gozerotypes "github.com/projectdiscovery/gozero/types"
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

func (request *Request) evalCode(ctx context.Context, input *gozero.Source) (*gozerotypes.Result, error) {
	if request.options.Options.DisableSandbox {
		return request.gozero.Eval(ctx, request.src, input)
	}

	if !dockerUnavailable.Load() {
		result, err := request.gozero.EvalWithVirtualEnv(ctx, request.confinementPolicy(), request.src, input)
		if err == nil || !errors.Is(err, confine.ErrConfinementUnavailable) {
			return result, err
		}
		if dockerUnavailable.CompareAndSwap(false, true) {
			gologger.Verbose().Msgf("docker sandbox unavailable for code templates, using native sandbox: %v", err)
		}
	}

	result, err := request.evalNative(ctx, input)
	if errors.Is(err, errNativeSandboxUnavailable) {
		if noSandboxReported.CompareAndSwap(false, true) {
			gologger.Error().Msgf("%s (%v)", noCodeSandboxMessage, err)
		}
		return nil, errkit.Wrap(ErrNoCodeSandbox, err.Error())
	}
	return result, err
}

func (request *Request) confinementPolicy() *confine.Policy {
	policy := confine.DefaultPolicy()
	// Code templates are untrusted process execution. Docker is preferred
	// because the payload sees only the image, not the host filesystem. When
	// Docker is not reachable, evalCode falls back to the native sandbox
	// (sandbox_native.go), and fails closed when none is available.
	policy.Backend = confine.BackendDocker
	// Run the payload as a non-root identity inside the container so a
	// hypothetical kernel/runc container escape maps to an unprivileged host uid
	// rather than root. 65534 is the conventional "nobody" uid/gid. The gozero
	// Docker backend widens the injected source to be readable by this uid.
	policy.RunAsUID = 65534
	policy.RunAsGID = 65534
	// NOTE(max-hardening): Docker+runc shares the host kernel, so this closes the
	// application-level escape surface (no shell injection, no unconfined
	// fallback, deny-by-default, non-root) but not a kernel/runc 0-day escape.
	// For hostile multi-tenant use, run the daemon on a kernel-isolating runtime
	// (gVisor runsc or Kata microVM) so a container escape does not reach the
	// host kernel.
	if request.Sandbox != nil && request.Sandbox.Image != "" {
		policy.DockerImage = request.Sandbox.Image
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
