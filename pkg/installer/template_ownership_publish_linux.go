//go:build linux

package installer

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func renameTemplateRestoreNoReplace(root *os.Root, temporaryPath, retiredPath string) error {
	sourceDirectory, err := root.Open(filepath.Dir(temporaryPath))
	if err != nil {
		return err
	}
	defer func() { _ = sourceDirectory.Close() }()

	destinationDirectory, err := root.Open(filepath.Dir(retiredPath))
	if err != nil {
		return err
	}
	defer func() { _ = destinationDirectory.Close() }()

	return unix.Renameat2(int(sourceDirectory.Fd()), filepath.Base(temporaryPath), int(destinationDirectory.Fd()), filepath.Base(retiredPath), unix.RENAME_NOREPLACE)
}
