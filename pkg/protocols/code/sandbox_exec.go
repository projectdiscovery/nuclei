package code

import (
	"context"
	"time"

	"github.com/projectdiscovery/gozero"
	"github.com/projectdiscovery/gozero/confine"
	gozerotypes "github.com/projectdiscovery/gozero/types"
)

func (request *Request) evalCode(ctx context.Context, input *gozero.Source) (*gozerotypes.Result, error) {
	if request.options.Options.DisableSandbox {
		return request.gozero.Eval(ctx, request.src, input)
	}

	return request.gozero.EvalWithVirtualEnv(ctx, request.confinementPolicy(), request.src, input)
}

func (request *Request) confinementPolicy() *confine.Policy {
	policy := confine.DefaultPolicy()
	// Code templates are untrusted process execution. Use Docker by default so
	// the payload cannot read arbitrary host files through native read-only
	// mounts; missing Docker is a hard error, not a fallback.
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
	if request.options != nil && request.options.Options != nil {
		if timeout := request.options.Options.GetTimeouts().CodeExecutionTimeout; timeout > 0 {
			policy.Timeout = time.Duration(timeout)
		}
	}
	return &policy
}
