package installer

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	osutils "github.com/projectdiscovery/utils/os"
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
	if osutils.IsWindows() {
		t.Skip("Skipping Zip LFI Check on Windows")
	}

	configuredTemplateDirectory := filepath.Join(os.TempDir(), "templates")
	defer func() {
		_ = os.RemoveAll(configuredTemplateDirectory)
	}()

	t.Run("negative scenarios", func(t *testing.T) {
		filePathsFromZip := []string{
			"./../nuclei-templates/../cve/test.yaml",
			"nuclei-templates/../cve/test.yaml",
			"nuclei-templates/././../cve/test.yaml",
			"nuclei-templates/.././../cve/test.yaml",
			"nuclei-templates/.././../cve/../test.yaml",
			"nuclei-templates/../templates-evil/test.yaml",
		}
		tm := TemplateManager{}

		for _, filePathFromZip := range filePathsFromZip {
			var tmp fs.FileInfo = &tempFileInfo{name: filePathFromZip}
			writePath := tm.getAbsoluteFilePath(configuredTemplateDirectory, filePathFromZip, tmp)
			require.Equal(t, "", writePath, filePathFromZip)
		}
	})

	t.Run("positive no-slash fallback", func(t *testing.T) {
		// Entry names with no slash exercise the fallback branch in
		// getAbsoluteFilePath. Legitimate single-name entries must still be
		// written into templateDir (regression test for the containment check
		// added to that branch).
		tm := TemplateManager{}
		var tmp fs.FileInfo = &tempFileInfo{name: "single-file.yaml"}
		writePath := tm.getAbsoluteFilePath(configuredTemplateDirectory, "single-file.yaml", tmp)
		require.Equal(t, filepath.Join(configuredTemplateDirectory, "single-file.yaml"), writePath)
	})

	t.Run("positive scenarios", func(t *testing.T) {
		filePathsFromZip := map[string]string{
			"nuclei-templates/cves/test.yaml": filepath.Join(configuredTemplateDirectory, "cves", "test.yaml"),
			"nuclei-templates/test.yaml":      filepath.Join(configuredTemplateDirectory, "test.yaml"),
		}
		tm := TemplateManager{}

		for filePathFromZip, expectedWritePath := range filePathsFromZip {
			var tmp fs.FileInfo = &tempFileInfo{name: filePathFromZip}
			writePath := tm.getAbsoluteFilePath(configuredTemplateDirectory, filePathFromZip, tmp)
			require.Equal(t, expectedWritePath, writePath, filePathFromZip)
		}
	})

	t.Run("positive symlinked template directory", func(t *testing.T) {
		realDir := t.TempDir()
		aliasDir := filepath.Join(t.TempDir(), "templates-link")
		require.NoError(t, os.Symlink(realDir, aliasDir))

		tm := TemplateManager{}
		var tmp fs.FileInfo = &tempFileInfo{name: "nuclei-templates/cves/test.yaml"}
		writePath := tm.getAbsoluteFilePath(aliasDir, "nuclei-templates/cves/test.yaml", tmp)
		require.Equal(t, filepath.Join(aliasDir, "cves", "test.yaml"), writePath)
	})

	// Regression: a malicious archive can target an entry whose intermediate
	// path component is itself a symlink that points outside the configured
	// templates directory. Because both the entry's leaf and its parent on
	// disk may be missing, a naive lexical containment check could miss the
	// escape. canonicalizePath inside IsPathWithinDirectory walks up to the
	// nearest existing ancestor (the symlink) and resolves it, which is what
	// makes this rejection sound. This test pins that behavior.
	t.Run("negative symlinked ancestor escapes templateDir", func(t *testing.T) {
		templateDir := t.TempDir()
		outsideDir := t.TempDir()
		// Plant a symlink "evil" inside templateDir that points outside.
		// A malicious zip entry that traverses through it must be rejected
		// before it ever reaches WriteFile / CreateFolder.
		require.NoError(t, os.Symlink(outsideDir, filepath.Join(templateDir, "evil")))

		tm := TemplateManager{}
		entries := []string{
			"nuclei-templates/evil/file.yaml",
			"nuclei-templates/evil/nested/file.yaml",
			"nuclei-templates/evil",
		}
		for _, entry := range entries {
			var tmp fs.FileInfo = &tempFileInfo{name: entry}
			writePath := tm.getAbsoluteFilePath(templateDir, entry, tmp)
			require.Equal(t, "", writePath, entry)
		}
	})
}
