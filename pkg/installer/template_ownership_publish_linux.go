//go:build linux

package installer

import (
	"errors"
	"fmt"
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

	err = unix.Renameat2(int(sourceDirectory.Fd()), filepath.Base(temporaryPath), int(destinationDirectory.Fd()), filepath.Base(retiredPath), unix.RENAME_NOREPLACE)
	return mapRenameNoReplaceError(err)
}

func mapRenameNoReplaceError(err error) error {
	if err == nil {
		return nil
	}

	switch {
	case errors.Is(err, unix.ENOSYS), errors.Is(err, unix.EINVAL), errors.Is(err, unix.EOPNOTSUPP):
		return fmt.Errorf("%w: %w", errors.ErrUnsupported, err)
	default:
		return err
	}
}
