// +build !windows

package engine

import (
	"syscall"
)

func kill(pid int) {
	_ = syscall.Kill(-pid, syscall.SIGKILL)
}
