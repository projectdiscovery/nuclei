//go:build !windows

package filepathutil

import (
	"os"
	"syscall"
)

// hardLinkCount returns the number of hard links to the file described by info.
// The second return value is false when the count cannot be determined.
func hardLinkCount(_ string, info os.FileInfo) (uint64, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return 0, false
	}
	return uint64(st.Nlink), true
}
