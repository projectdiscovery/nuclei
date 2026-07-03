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
