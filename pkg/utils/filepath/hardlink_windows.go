//go:build windows

package filepathutil

import (
	"os"
	"syscall"
)

// fileFlagOpenReparsePoint opens the reparse point itself instead of following
// it, so a symlinked path is not silently resolved while inspecting link count.
// It is not exported by the syscall package, so it is defined locally.
const fileFlagOpenReparsePoint = 0x00200000

// hardLinkCount returns the number of hard links to the file at path using the
// Windows file information API. The second return value is false when the count
// cannot be determined, in which case the caller treats the file as not
// hard-linked (regular includes must keep working on Windows).
func hardLinkCount(path string, _ os.FileInfo) (uint64, bool) {
	if path == "" {
		return 0, false
	}

	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, false
	}

	// open with metadata-only access; FILE_FLAG_BACKUP_SEMANTICS lets the open
	// succeed regardless of the object type and OPEN_REPARSE_POINT avoids
	// following a symlink to its target.
	handle, err := syscall.CreateFile(
		pathPtr,
		0,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_FLAG_BACKUP_SEMANTICS|fileFlagOpenReparsePoint,
		0,
	)
	if err != nil {
		return 0, false
	}
	defer syscall.CloseHandle(handle)

	var info syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(handle, &info); err != nil {
		return 0, false
	}
	return uint64(info.NumberOfLinks), true
}
