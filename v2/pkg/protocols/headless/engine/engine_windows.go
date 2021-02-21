// +build windows

package engine

import (
	"os/exec"
	"strconv"
)

func kill(pid int) {
	_ = exec.Command("taskkill", "/t", "/f", "/pid", strconv.Itoa(pid)).Run()
}
