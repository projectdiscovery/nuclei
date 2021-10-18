package targets

import (
	"io"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
)

// TargetsRepository stores targets on disk and provides
// functions to access them and add/update/delete them.
type TargetsRepository struct {
	root string
}

// NewTargetsRepository creates a new target repository
func NewTargetsRepository(directory string) *TargetsRepository {
	return &TargetsRepository{root: directory}
}

// Get returns an io.Reader for a targetPath
func (t *TargetsRepository) Get(targetPath string) (io.Reader, error) {
	targetPathFinal := filepath.Join(t.root, targetPath)
	return os.Open(targetPathFinal)
}

// Add adds a target to the disk. If append is specified, the
// target is updated with the new input
func (t *TargetsRepository) Add(targetPath string, data io.Reader, append bool) error {
	targetPathFinal := filepath.Join(t.root, targetPath)

	var file *os.File
	var err error
	if append {
		file, err = os.OpenFile(targetPathFinal, os.O_APPEND|os.O_WRONLY|os.O_CREATE, os.ModePerm)
	} else {
		file, err = os.Create(targetPathFinal)
	}
	if err != nil {
		return errors.Wrap(err, "could not create target")
	}
	defer file.Close()

	if _, err = io.Copy(file, data); err != nil {
		return errors.Wrap(err, "could not write target data")
	}
	return nil
}

// Delete deletes a target with a targetPath
func (t *TargetsRepository) Delete(targetPath string) error {
	targetPathFinal := filepath.Join(t.root, targetPath)
	return os.Remove(targetPathFinal)
}
