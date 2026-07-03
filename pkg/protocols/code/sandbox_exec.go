package code

import (
	"context"
	"io"
	"os"
	"os/exec"

	"github.com/projectdiscovery/gozero"
	"github.com/projectdiscovery/gozero/sandbox"
	gozerotypes "github.com/projectdiscovery/gozero/types"
)

func resolveEngine(engines []string) (string, error) {
	for _, engine := range engines {
		if path, err := exec.LookPath(engine); err == nil {
			return path, nil
		}
	}
	return "", gozero.ErrNoValidEngine
}

func mergeVariables(sources ...*gozero.Source) map[string]string {
	env := make(map[string]string)
	for _, source := range sources {
		if source == nil {
			continue
		}
		for _, variable := range source.Variables {
			env[variable.Name] = variable.Value
		}
	}
	return env
}

func readSourceStdin(input *gozero.Source) (string, error) {
	if input == nil {
		return "", nil
	}
	if input.File != nil {
		if _, err := input.File.Seek(0, io.SeekStart); err == nil {
			data, err := io.ReadAll(input.File)
			if err == nil {
				return string(data), nil
			}
		}
	}
	if input.Filename == "" {
		return "", nil
	}
	data, err := os.ReadFile(input.Filename)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (request *Request) evalCode(ctx context.Context, input *gozero.Source) (*gozerotypes.Result, error) {
	if request.useSandbox() {
		return request.gozero.EvalWithVirtualEnv(
			ctx,
			gozero.VirtualEnvDocker,
			request.src,
			input,
			&sandbox.DockerConfiguration{
				WorkingDir: request.Sandbox.WorkingDir,
				Image:      request.Sandbox.Image,
			},
		)
	}
	if result, ok, err := request.tryEvalSandboxed(ctx, input); ok || err != nil {
		return result, err
	}
	return request.gozero.Eval(ctx, request.src, input)
}
