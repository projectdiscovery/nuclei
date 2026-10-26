//go:build darwin

package code

import (
	"fmt"
	"os/exec"
	"sync"
)

// macHiddenDirs are denied to the payload for reads and writes: every home
// directory and root's home.
var macHiddenDirs = []string{"/Users", "/var/root"}

var detectNativeSandbox = sync.OnceValues(func() (*nativeLauncher, error) {
	bin, err := exec.LookPath("sandbox-exec")
	if err != nil {
		return nil, fmt.Errorf("%w: sandbox-exec not found: %v", errNativeSandboxUnavailable, err)
	}
	// Probe once: sandbox-exec exists on every macOS, but it can still be
	// unusable (for example inside another sandbox).
	if out, err := exec.Command(bin, "-p", "(version 1)(allow default)", "/usr/bin/true").CombinedOutput(); err != nil {
		return nil, fmt.Errorf("%w: sandbox-exec probe failed: %v: %s", errNativeSandboxUnavailable, err, out)
	}
	return &nativeLauncher{
		name: "seatbelt",
		bin:  bin,
		wrap: func(workspace string, env map[string]string, command []string) ([]string, []string) {
			argv := append([]string{bin, "-p", seatbeltProfile(workspace, hiddenDirs(macHiddenDirs...))}, command...)
			// sandbox-exec passes its own environment to the child.
			return argv, envSlice(env)
		},
	}, nil
})
