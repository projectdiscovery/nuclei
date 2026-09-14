//go:build !linux && !darwin && !windows

package installer

import (
	"errors"
	"os"
)

func renameTemplateRestoreNoReplace(_ *os.Root, _, _ string) error {
	return errors.ErrUnsupported
}
