package installer

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var _ fs.FileInfo = &tempFileInfo{}

type tempFileInfo struct {
	name string
}

func (t *tempFileInfo) Name() string {
	return t.name
}

func (t *tempFileInfo) ModTime() time.Time {
	return time.Now()
}

func (t *tempFileInfo) Mode() fs.FileMode {
	return fs.ModePerm
}

func (t tempFileInfo) IsDir() bool {
	return false
}

func (t *tempFileInfo) Size() int64 {
	return 100
}

func (t *tempFileInfo) Sys() any {
	return nil
}

func TestZipSlip(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping Unix Zip LFI Check")
	}

	configuredTemplateDirectory := filepath.Join(os.TempDir(), "templates")
	defer os.RemoveAll(configuredTemplateDirectory)

	t.Run("negative scenarios", func(t *testing.T) {
		filePathsFromZip := []string{
			"./../nuclei-templates/../cve/test.yaml",
			"nuclei-templates/../cve/test.yaml",
			"nuclei-templates/././../cve/test.yaml",
			"nuclei-templates/.././../cve/test.yaml",
			"nuclei-templates/.././../cve/../test.yaml",
		}
		tm := TemplateManager{}

		for _, filePathFromZip := range filePathsFromZip {
			var tmp fs.FileInfo = &tempFileInfo{name: filePathFromZip}
			writePath := tm.getAbsoluteFilePath(configuredTemplateDirectory, filePathFromZip, tmp)
			require.Equal(t, "", writePath, filePathFromZip)
		}
	})
}
