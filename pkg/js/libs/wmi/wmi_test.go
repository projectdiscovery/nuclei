package wmi

import (
	"context"
	"testing"

	"github.com/projectdiscovery/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/libs/goexec"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/utils"
)

func TestCommandMapsAdapterRequest(t *testing.T) {
	var got goexec.Request
	restore := goexec.SetRunnerForTesting(runnerFunc(func(_ context.Context, req goexec.Request) (*goexec.Result, error) {
		got = req
		return &goexec.Result{
			OK:              true,
			Module:          req.Module,
			Method:          req.Method,
			Target:          req.Target,
			ExitCode:        0,
			OutputCollected: req.Options.Output,
			OutputMethod:    req.Options.OutputMethod,
		}, nil
	}))
	defer restore()

	client := &Client{
		target:  "windows01",
		auth:    goexec.Password("CORP\\auditor", "secret"),
		options: goexec.DefaultExecutionOptions(),
		nj:      utils.NewNucleiJS(goja.New()),
	}
	result := client.Command("whoami /all", map[string]interface{}{"output": true, "timeout": float64(7)})
	if result["ok"] != true {
		t.Fatalf("expected ok result, got %#v", result)
	}
	if got.Module != "wmi" || got.Method != "command" || got.Command != "whoami /all" {
		t.Fatalf("unexpected request: %#v", got)
	}
	if !got.Options.Output || got.Options.Timeout != 7 {
		t.Fatalf("unexpected options: %#v", got.Options)
	}
}

type runnerFunc func(context.Context, goexec.Request) (*goexec.Result, error)

func (f runnerFunc) Run(ctx context.Context, req goexec.Request) (*goexec.Result, error) {
	return f(ctx, req)
}
