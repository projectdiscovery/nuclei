//go:build linux || darwin

package code

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/projectdiscovery/gozero"
	gozerotypes "github.com/projectdiscovery/gozero/types"
)

// nativeKillGrace bounds how long Wait may block on inherited pipes after the
// process group is killed.
const nativeKillGrace = 5 * time.Second

// evalNative runs the code template in the native sandbox of this OS. The
// source is copied into a fresh workspace, so the payload never needs read
// access to nuclei's own directories.
func (request *Request) evalNative(ctx context.Context, input *gozero.Source) (*gozerotypes.Result, error) {
	launcher, err := detectNativeSandbox()
	if err != nil {
		return nil, err
	}
	engine, err := request.resolveEngine()
	if err != nil {
		return nil, err
	}
	script, err := os.ReadFile(request.src.Filename)
	if err != nil {
		return nil, err
	}

	if timeout := request.codeTimeout(); timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	base := ""
	if request.options != nil {
		base = request.options.TemporaryDirectory
	}
	workspace, err := os.MkdirTemp(base, "nuclei-code-*")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(workspace) }()
	if resolved, err := filepath.EvalSymlinks(workspace); err == nil {
		workspace = resolved
	}
	scriptPath := filepath.Join(workspace, filepath.Base(request.src.Filename))
	if err := os.WriteFile(scriptPath, script, 0o600); err != nil {
		return nil, err
	}

	vars := make(map[string]string, len(request.src.Variables)+len(input.Variables))
	for _, v := range request.src.Variables {
		vars[v.Name] = v.Value
	}
	for _, v := range input.Variables {
		vars[v.Name] = v.Value
	}
	command := append([]string{engine}, request.Args...)
	command = append(command, scriptPath)

	argv, env := launcher.wrap(workspace, nativeEnv(workspace, vars), command)
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = nativeKillGrace
	cmd.Env = env
	cmd.Dir = workspace
	if input.File != nil {
		cmd.Stdin = input.File
	}

	result := &gozerotypes.Result{Command: cmd.String()}
	if request.gozero != nil && request.gozero.Options != nil && request.gozero.Options.DebugMode {
		result.DebugData = &bytes.Buffer{}
		cmd.Stdout = io.MultiWriter(&result.Stdout, result.DebugData)
		cmd.Stderr = io.MultiWriter(&result.Stderr, result.DebugData)
	} else {
		cmd.Stdout = &result.Stdout
		cmd.Stderr = &result.Stderr
	}
	if err := cmd.Start(); err != nil {
		return result, fmt.Errorf("could not start %s sandbox: %w", launcher.name, err)
	}
	if err := cmd.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.SetExitError(exitErr)
			result.SetExitCode(exitErr.ExitCode())
		}
		return result, fmt.Errorf("code failed in %s sandbox: %w: %s", launcher.name, err, result.Stderr.String())
	}
	return result, nil
}

// resolveEngine finds the first engine of the template on the host PATH, the
// same way gozero picks its interpreter.
func (request *Request) resolveEngine() (string, error) {
	for _, engine := range request.Engine {
		if path, err := exec.LookPath(engine); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("engines %v not available on host", request.Engine)
}

// nativeLauncher wraps a command in the native sandbox of this OS.
type nativeLauncher struct {
	name string
	bin  string
	wrap func(workspace string, env map[string]string, command []string) (argv []string, environ []string)
}
