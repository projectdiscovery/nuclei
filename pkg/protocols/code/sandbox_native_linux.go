//go:build linux

package code

import (
	"fmt"
	"os"
	"os/exec"
	"sync"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/sandbox"
)

// linuxHiddenDirs are replaced with empty tmpfs mounts for the payload: every
// home directory, root's home, and the runtime directories that hold sockets
// such as the Docker socket (unix sockets do not need network access).
var linuxHiddenDirs = []string{"/home", "/root", "/run", "/var/run"}

var detectNativeSandbox = sync.OnceValues(func() (*nativeLauncher, error) {
	if sandbox.Enforced() {
		// Landlock forbids mount(2) in this process and its children, and
		// bubblewrap needs mounts to build the sandbox.
		return nil, fmt.Errorf("%w: bwrap cannot run under the landlock process sandbox", errNativeSandboxUnavailable)
	}
	bin, err := exec.LookPath("bwrap")
	if err != nil {
		return nil, fmt.Errorf("%w: bwrap not found: %v", errNativeSandboxUnavailable, err)
	}
	trueBin, err := exec.LookPath("true")
	if err != nil {
		return nil, fmt.Errorf("%w: true not found for the bwrap probe: %v", errNativeSandboxUnavailable, err)
	}
	// Probe once with the same isolation the payload gets: bwrap is often
	// installed where user namespaces are not allowed (for example in
	// unprivileged containers).
	probeDir, err := os.MkdirTemp("", "nuclei-bwrap-probe-*")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errNativeSandboxUnavailable, err)
	}
	defer func() { _ = os.RemoveAll(probeDir) }()
	probe := bwrapArgs(bin, probeDir, hiddenDirs(linuxHiddenDirs...), nil, []string{trueBin})
	if out, err := exec.Command(probe[0], probe[1:]...).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("%w: bwrap probe failed: %v: %s", errNativeSandboxUnavailable, err, out)
	}
	return &nativeLauncher{
		name: "bubblewrap",
		bin:  bin,
		wrap: func(workspace string, env map[string]string, command []string) ([]string, []string) {
			// bwrap clears the environment and sets the payload one itself.
			return bwrapArgs(bin, workspace, hiddenDirs(linuxHiddenDirs...), env, command), []string{}
		},
	}, nil
})
