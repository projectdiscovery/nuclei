package installer

import (
	"errors"
	"io/fs"
	"os"
)

func syncTemplateOwnershipFile(root *os.Root, relativePath string, mode fs.FileMode) error {
	return syncTemplateOwnershipFileWithOpen(root, relativePath, mode, func() (*os.File, error) {
		return root.OpenFile(relativePath, os.O_RDWR, 0)
	})
}

func syncTemplateOwnershipFileWithOpen(root *os.Root, relativePath string, mode fs.FileMode, open func() (*os.File, error)) error {
	if err := root.Chmod(relativePath, 0o600); err != nil {
		return err
	}

	file, err := open()
	if err != nil {
		return errors.Join(err, root.Chmod(relativePath, mode.Perm()))
	}

	if err := file.Chmod(mode.Perm()); err != nil {
		return errors.Join(err, file.Close(), root.Chmod(relativePath, mode.Perm()))
	}

	return errors.Join(file.Sync(), file.Close())
}

// Windows cannot flush the read-only directory handle exposed by os.Root.
func syncTemplateOwnershipDirectory(_ *os.Root, _ string) error {
	return nil
}
