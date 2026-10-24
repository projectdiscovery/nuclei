package dsl

import (
	"runtime"
	"strconv"
	"strings"
)

// goid returns the current goroutine id.
//
// DSL helpers have no call-site context argument, so file() scopes its
// LoadHelperFile sandbox to the executing goroutine while a template runs.
func goid() uint64 {
	var buf [64]byte
	n := runtime.Stack(buf[:], false)
	s := string(buf[:n])
	s = strings.TrimPrefix(s, "goroutine ")
	if i := strings.IndexByte(s, ' '); i > 0 {
		id, err := strconv.ParseUint(s[:i], 10, 64)
		if err == nil {
			return id
		}
	}
	return 0
}
