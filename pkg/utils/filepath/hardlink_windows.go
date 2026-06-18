//go:build windows

package filepathutil

import "os"

// hardLinkCount cannot be determined from the standard FileInfo on Windows,
// so it always reports that the count is unknown.
func hardLinkCount(info os.FileInfo) (uint64, bool) {
	return 0, false
}
