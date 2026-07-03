//go:build linux

package code

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gozero"
	gozerotypes "github.com/projectdiscovery/gozero/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/utils/errkit"
)

const nucleiCodeSourceMount = "/nuclei-src"

var (
	bubblewrapMissingOnce sync.Once
)

func bubblewrapAvailable(ctx context.Context) bool {
	cmd := exec.CommandContext(ctx, "bwrap", "--version")
	return cmd.Run() == nil
}

func bubblewrapFunctional(ctx context.Context) bool {
	if !bubblewrapAvailable(ctx) {
		return false
	}
	cmd := exec.CommandContext(ctx, "bwrap",
		"--ro-bind", "/bin", "/bin",
		"--ro-bind", "/usr", "/usr",
		"--", "/bin/true",
	)
	return cmd.Run() == nil
}

func (request *Request) tryEvalSandboxed(ctx context.Context, input *gozero.Source) (*gozerotypes.Result, bool, error) {
	if request.options.Options.DisableSandbox {
		return nil, false, nil
	}
	if !bubblewrapAvailable(ctx) {
		bubblewrapMissingOnce.Do(func() {
			gologger.Warning().Msg("bubblewrap (bwrap) not available; code templates run without OS sandbox (use --no-sandbox only to disable when bwrap is present)")
		})
		return nil, false, nil
	}

	engine, err := resolveEngine(request.Engine)
	if err != nil {
		return nil, false, err
	}

	result, err := evalBubblewrap(ctx, request, engine, input)
	if shouldFallbackFromBubblewrap(result, err) {
		gologger.Warning().Msgf("bubblewrap sandbox unavailable, falling back to unsandboxed code execution: %v", err)
		return nil, false, nil
	}
	return result, true, err
}

func shouldFallbackFromBubblewrap(result *gozerotypes.Result, err error) bool {
	if isBubblewrapRuntimeError(err) {
		return true
	}
	if result == nil {
		return false
	}
	stderr := strings.ToLower(result.Stderr.String())
	return strings.Contains(stderr, "creating new namespace failed") ||
		strings.Contains(stderr, "no permissions to create new namespace")
}

func isBubblewrapRuntimeError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "namespace") ||
		strings.Contains(msg, "operation not permitted") ||
		strings.Contains(msg, "permission denied") && strings.Contains(msg, "bwrap")
}

func evalBubblewrap(ctx context.Context, request *Request, engine string, input *gozero.Source) (*gozerotypes.Result, error) {
	scriptDir := filepath.Dir(request.src.Filename)
	scriptName := filepath.Base(request.src.Filename)
	scriptInSandbox := filepath.Join(nucleiCodeSourceMount, scriptName)

	stdin, err := readSourceStdin(input)
	if err != nil {
		return nil, errkit.Wrap(err, "could not read code stdin")
	}

	env := mergeVariables(request.src, input)
	if _, ok := env["PATH"]; !ok {
		env["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	}

	args := append(append([]string{}, request.gozero.Options.Args...), scriptInSandbox)
	bwrapArgs := []string{
		"--die-with-parent",
		"--proc", "/proc",
		"--dev", "/dev",
		"--tmpfs", "/tmp",
		"--tmpfs", "/run",
		"--ro-bind", "/usr", "/usr",
		"--ro-bind", "/bin", "/bin",
		"--ro-bind", "/lib", "/lib",
		"--bind", scriptDir, nucleiCodeSourceMount,
	}
	if lib64, err := os.Stat("/lib64"); err == nil && lib64.IsDir() {
		bwrapArgs = append(bwrapArgs, "--ro-bind", "/lib64", "/lib64")
	}
	for _, root := range protocolstate.AllowedFileRoots(request.options.Options) {
		cleanRoot := filepath.Clean(root)
		if cleanRoot == scriptDir {
			continue
		}
		if info, statErr := os.Stat(cleanRoot); statErr != nil || !info.IsDir() {
			continue
		}
		bwrapArgs = append(bwrapArgs, "--ro-bind", cleanRoot, cleanRoot)
	}
	if request.options.Interactsh == nil {
		bwrapArgs = append(bwrapArgs, "--unshare-net")
	}
	for key, value := range env {
		bwrapArgs = append(bwrapArgs, "--setenv", key, value)
	}
	bwrapArgs = append(bwrapArgs, "--", engine)
	bwrapArgs = append(bwrapArgs, args...)

	cmd := exec.CommandContext(ctx, "bwrap", bwrapArgs...)
	result := &gozerotypes.Result{Command: cmd.String()}
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	cmd.Stdout = &result.Stdout
	cmd.Stderr = &result.Stderr

	if err := cmd.Start(); err != nil {
		return result, fmt.Errorf("bwrap: %w", err)
	}
	if err := cmd.Wait(); err != nil {
		if execErr, ok := err.(*exec.ExitError); ok {
			result.SetExitError(execErr)
		}
		return result, errkit.Wrap(err, "sandboxed code execution failed")
	}
	return result, nil
}
