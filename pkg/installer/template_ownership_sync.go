//go:build !windows

package installer

import (
	"errors"
	"io/fs"
	"os"
)

func syncTemplateOwnershipFile(root *os.Root, relativePath string, mode fs.FileMode) error {
	file, err := root.Open(relativePath)
	if err != nil {
		return err
	}

	if err := file.Chmod(mode.Perm()); err != nil {
		_ = file.Close()
		return err
	}

	return errors.Join(file.Sync(), file.Close())
}

func syncTemplateOwnershipDirectory(root *os.Root, relativePath string) error {
	directory, err := root.Open(relativePath)
	if err != nil {
		return err
	}

	defer func() { _ = directory.Close() }()

	return directory.Sync()
}
