package installer

import (
	"archive/zip"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	fileutil "github.com/projectdiscovery/utils/file"
	"github.com/stretchr/testify/require"
)

func newWrittenTemplates(t *testing.T, paths ...string) map[string]string {
	t.Helper()
	written := make(map[string]string)
	for _, templatePath := range paths {
		contents, err := os.ReadFile(templatePath)
		require.NoError(t, err)
		written[templatePath] = templateDigest(contents)
	}
	return written
}

func seedTemplateOwnership(t *testing.T, dir string, paths ...string) {
	t.Helper()
	manifest := &templateOwnershipManifest{
		Version: templateOwnershipVersion,
		Files:   make(map[string]string, len(paths)),
	}
	for _, templatePath := range paths {
		contents, err := os.ReadFile(templatePath)
		require.NoError(t, err)
		relativePath, err := filepath.Rel(dir, templatePath)
		require.NoError(t, err)
		manifest.Files[filepath.ToSlash(relativePath)] = templateDigest(contents)
	}
	require.NoError(t, validateTemplateOwnership(manifest))
	require.NoError(t, writeTemplateOwnership(dir, manifest))
}

func newTemplateReleaseArchive(t *testing.T, archivePath string, contents []byte) *bytes.Reader {
	t.Helper()
	var archive bytes.Buffer
	zipWriter := zip.NewWriter(&archive)
	entry, err := zipWriter.Create(archivePath)
	require.NoError(t, err)
	_, err = entry.Write(contents)
	require.NoError(t, err)
	require.NoError(t, zipWriter.Close())
	return bytes.NewReader(archive.Bytes())
}

func TestValidateTemplateOwnershipPath(t *testing.T) {
	invalidPaths := []string{
		"",
		"/absolute.yaml",
		`nested\template.yaml`,
		"C:/volume.yaml",
		"../outside.yaml",
		"nested/../template.yaml",
		"nested//template.yaml",
		"nul\x00.yaml",
		"README.md",
	}
	for _, relativePath := range invalidPaths {
		t.Run(relativePath, func(t *testing.T) {
			require.Error(t, validateTemplateOwnershipPath(relativePath))
		})
	}
	require.NoError(t, validateTemplateOwnershipPath("http/example.yaml"))
}

func TestBuildTemplateOwnershipSkipsNonTemplateOutputsBeforeRelativizing(t *testing.T) {
	templatesDir := t.TempDir()
	nonTemplatePath := filepath.Join(t.TempDir(), config.NucleiIgnoreFileName)
	if volume := filepath.VolumeName(templatesDir); volume != "" {
		otherVolume := "Z:"
		if strings.EqualFold(volume, otherVolume) {
			otherVolume = "Y:"
		}
		nonTemplatePath = otherVolume + string(os.PathSeparator) + config.NucleiIgnoreFileName
	}

	manifest, err := buildTemplateOwnership(templatesDir, map[string]string{
		nonTemplatePath: templateDigest([]byte("ignore contents")),
	})
	require.NoError(t, err)
	require.Empty(t, manifest.Files)
}

func TestBuildTemplateOwnershipSkipsExcludedTemplateDirectories(t *testing.T) {
	templatesDir := t.TempDir()
	helperPath := filepath.Join(templatesDir, "helpers", "payloads", "swagger.json")

	manifest, err := buildTemplateOwnership(templatesDir, map[string]string{
		helperPath: templateDigest([]byte("helper contents")),
	})
	require.NoError(t, err)
	require.Empty(t, manifest.Files)
}

func TestBootstrapTemplateOwnershipFromArchive(t *testing.T) {
	templatesDir := t.TempDir()
	retiredTemplate := filepath.Join(templatesDir, "http", "retired.yaml")
	localTemplate := filepath.Join(templatesDir, "local.yaml")
	releaseContents := []byte("release contents")
	require.NoError(t, os.Mkdir(filepath.Dir(retiredTemplate), 0755))
	require.NoError(t, os.WriteFile(retiredTemplate, releaseContents, 0644))
	require.NoError(t, os.WriteFile(localTemplate, []byte("local contents"), 0644))

	tm := &TemplateManager{}
	archive := newTemplateReleaseArchive(t, "projectdiscovery-nuclei-templates-release/http/retired.yaml", releaseContents)
	require.NoError(t, tm.bootstrapTemplateOwnershipFromArchive(templatesDir, archive))
	manifest, err := loadTemplateOwnership(templatesDir)
	require.NoError(t, err)
	require.Equal(t, map[string]string{"http/retired.yaml": templateDigest(releaseContents)}, manifest.Files)

	require.NoError(t, reconcileTemplateOwnership(templatesDir, newWrittenTemplates(t)))
	require.NoFileExists(t, retiredTemplate, "unchanged templates retired from the legacy release should be removed")
	require.FileExists(t, localTemplate, "files absent from the official prior release must remain unowned")
}

func TestBootstrapTemplateOwnershipSkipsNonOwnedOutputs(t *testing.T) {
	testCases := []string{
		config.NucleiIgnoreFileName,
		"helpers/payloads/swagger.json",
	}
	for _, archivePath := range testCases {
		t.Run(archivePath, func(t *testing.T) {
			templatesDir := t.TempDir()
			archive := newTemplateReleaseArchive(t, "projectdiscovery-nuclei-templates-release/"+archivePath, []byte("non-template contents"))

			tm := &TemplateManager{}
			require.NoError(t, tm.bootstrapTemplateOwnershipFromArchive(templatesDir, archive))
			manifest, err := loadTemplateOwnership(templatesDir)
			require.NoError(t, err)
			require.Empty(t, manifest.Files)
		})
	}
}

func TestBootstrapTemplateOwnershipUsesArchiveFetcher(t *testing.T) {
	tm := &TemplateManager{}

	t.Run("writes ownership from fetched prior release", func(t *testing.T) {
		templatesDir := t.TempDir()
		contents := []byte("release contents")
		archive := newTemplateReleaseArchive(t, "projectdiscovery-nuclei-templates-release/http/official.yaml", contents)
		var fetchedVersion string
		err := tm.bootstrapTemplateOwnership(templatesDir, "v1.2.3", func(version string) (*bytes.Reader, error) {
			fetchedVersion = version
			return archive, nil
		})
		require.NoError(t, err)
		require.Equal(t, "v1.2.3", fetchedVersion)
		manifest, err := loadTemplateOwnership(templatesDir)
		require.NoError(t, err)
		require.Equal(t, map[string]string{"http/official.yaml": templateDigest(contents)}, manifest.Files)
	})

	t.Run("continues after fetch failure without writing ownership", func(t *testing.T) {
		templatesDir := t.TempDir()
		err := tm.bootstrapTemplateOwnership(templatesDir, "v1.2.3", func(string) (*bytes.Reader, error) {
			return nil, errors.New("fetch failed")
		})
		require.NoError(t, err)
		_, loadErr := loadTemplateOwnership(templatesDir)
		require.ErrorIs(t, loadErr, errTemplateOwnershipMissing)
	})

	t.Run("continues after invalid prior archive", func(t *testing.T) {
		templatesDir := t.TempDir()
		err := tm.bootstrapTemplateOwnership(templatesDir, "v1.2.3", func(string) (*bytes.Reader, error) {
			return bytes.NewReader([]byte("not a release archive")), nil
		})
		require.NoError(t, err)
		_, loadErr := loadTemplateOwnership(templatesDir)
		require.ErrorIs(t, loadErr, errTemplateOwnershipMissing)
	})
}

func TestBootstrapTemplateOwnershipHandlesInvalidManifest(t *testing.T) {
	t.Run("replaces invalid manifest when no recovery is pending", func(t *testing.T) {
		templatesDir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(templatesDir, templateOwnershipFileName), []byte("not json"), 0600))
		fetchCalled := false
		tm := &TemplateManager{}
		require.NoError(t, tm.bootstrapTemplateOwnership(templatesDir, "v1.2.3", func(string) (*bytes.Reader, error) {
			fetchCalled = true
			return nil, errors.New("unexpected fetch")
		}))
		require.False(t, fetchCalled)

		templatePath := filepath.Join(templatesDir, "official.yaml")
		require.NoError(t, os.WriteFile(templatePath, []byte("release contents"), 0644))
		require.NoError(t, reconcileTemplateOwnership(templatesDir, newWrittenTemplates(t, templatePath)))
		manifest, err := loadTemplateOwnership(templatesDir)
		require.NoError(t, err)
		require.Contains(t, manifest.Files, "official.yaml")
	})

	t.Run("rejects invalid manifest when recovery is pending", func(t *testing.T) {
		templatesDir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(templatesDir, templateOwnershipFileName), []byte("not json"), 0600))
		require.NoError(t, os.WriteFile(filepath.Join(templatesDir, retiredTemplateQuarantinePath("retired.yaml")), []byte("quarantined contents"), 0600))
		tm := &TemplateManager{}
		err := tm.bootstrapTemplateOwnership(templatesDir, "v1.2.3", func(string) (*bytes.Reader, error) {
			return nil, errors.New("unexpected fetch")
		})
		require.ErrorContains(t, err, "decode template ownership metadata")
	})

	t.Run("rejects invalid manifest when restore state is pending", func(t *testing.T) {
		templatesDir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(templatesDir, templateOwnershipFileName), []byte("not json"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(templatesDir, templateRestoreStatePrefix("retired.yaml")+strings.Repeat("a", 32)), nil, 0o600))
		tm := &TemplateManager{}
		err := tm.bootstrapTemplateOwnership(templatesDir, "v1.2.3", func(string) (*bytes.Reader, error) {
			return nil, errors.New("unexpected fetch")
		})
		require.ErrorContains(t, err, "decode template ownership metadata")
	})
}

func TestReconcileTemplateOwnershipUsesWrittenContents(t *testing.T) {
	templatesDir := t.TempDir()
	templatePath := filepath.Join(templatesDir, "official.yaml")
	releaseContents := []byte("release contents")
	localContents := []byte("concurrent local edit")
	require.NoError(t, os.WriteFile(templatePath, releaseContents, 0644))

	written := map[string]string{templatePath: templateDigest(releaseContents)}
	require.NoError(t, os.WriteFile(templatePath, localContents, 0644))
	require.NoError(t, reconcileTemplateOwnership(templatesDir, written))

	manifest, err := loadTemplateOwnership(templatesDir)
	require.NoError(t, err)
	require.Equal(t, written[templatePath], manifest.Files["official.yaml"])
	require.NoError(t, reconcileTemplateOwnership(templatesDir, newWrittenTemplates(t)))
	contents, err := os.ReadFile(templatePath)
	require.NoError(t, err)
	require.Equal(t, localContents, contents, "a concurrent local edit must not be certified as release-owned or deleted")
}

func TestRecordPartialTemplateOwnershipPreservesUnvisitedPaths(t *testing.T) {
	templatesDir := t.TempDir()
	visitedPath := filepath.Join(templatesDir, "visited.yaml")
	unvisitedPath := filepath.Join(templatesDir, "unvisited.yaml")
	addedPath := filepath.Join(templatesDir, "added.yaml")
	require.NoError(t, os.WriteFile(visitedPath, []byte("old visited contents"), 0644))
	require.NoError(t, os.WriteFile(unvisitedPath, []byte("unvisited contents"), 0644))
	seedTemplateOwnership(t, templatesDir, visitedPath, unvisitedPath)

	require.NoError(t, os.WriteFile(visitedPath, []byte("new visited contents"), 0644))
	require.NoError(t, os.WriteFile(addedPath, []byte("partially added contents"), 0644))
	require.NoError(t, recordPartialTemplateOwnership(templatesDir, newWrittenTemplates(t, visitedPath, addedPath)))

	manifest, err := loadTemplateOwnership(templatesDir)
	require.NoError(t, err)
	require.Equal(t, templateDigest([]byte("new visited contents")), manifest.Files["visited.yaml"])
	require.Equal(t, templateDigest([]byte("unvisited contents")), manifest.Files["unvisited.yaml"])
	require.Equal(t, templateDigest([]byte("partially added contents")), manifest.Files["added.yaml"])

	require.NoError(t, reconcileTemplateOwnership(templatesDir, newWrittenTemplates(t)))
	require.NoFileExists(t, visitedPath)
	require.NoFileExists(t, unvisitedPath)
	require.NoFileExists(t, addedPath, "a later release that omits the partially added path must retire it")
}

func TestReconcileTemplateOwnershipPreservesCurrentFileAlias(t *testing.T) {
	templatesDir := t.TempDir()
	currentPath := filepath.Join(templatesDir, "official.yaml")
	retiredPath := filepath.Join(templatesDir, "Official.yaml")
	contents := []byte("release contents")
	require.NoError(t, os.WriteFile(currentPath, contents, 0644))
	if err := os.Link(currentPath, retiredPath); err != nil {
		if _, statErr := os.Stat(retiredPath); statErr != nil {
			t.Skipf("filesystem aliases are unavailable: %v", err)
		}
	}

	seedTemplateOwnership(t, templatesDir, retiredPath)
	require.NoError(t, reconcileTemplateOwnership(templatesDir, newWrittenTemplates(t, currentPath)))
	require.FileExists(t, currentPath)
	require.FileExists(t, retiredPath, "cleanup must not remove a path that aliases a current release template")
}

func TestReconcileTemplateOwnershipPreservesNonRegularRetiredPath(t *testing.T) {
	templatesDir := t.TempDir()
	retiredPath := filepath.Join(templatesDir, "retired.yaml")
	require.NoError(t, os.WriteFile(retiredPath, []byte("release contents"), 0644))
	seedTemplateOwnership(t, templatesDir, retiredPath)
	require.NoError(t, os.Remove(retiredPath))
	require.NoError(t, os.Mkdir(retiredPath, 0755))

	require.NoError(t, reconcileTemplateOwnership(templatesDir, newWrittenTemplates(t)))
	require.DirExists(t, retiredPath)
	require.NoFileExists(t, filepath.Join(templatesDir, retiredTemplateQuarantinePath("retired.yaml")))
	manifest, err := loadTemplateOwnership(templatesDir)
	require.NoError(t, err)
	require.Empty(t, manifest.Files, "non-regular replacements should relinquish installer ownership")
}

func TestCleanupQuarantinedTemplatePreservesConcurrentReplacement(t *testing.T) {
	templatesDir := t.TempDir()
	root, err := os.OpenRoot(templatesDir)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, root.Close()) })

	retiredPath := "retired.yaml"
	releaseContents := []byte("release contents")
	replacementContents := []byte("concurrent user replacement")
	require.NoError(t, root.WriteFile(retiredPath, releaseContents, 0644))
	quarantinePath := retiredTemplateQuarantinePath(retiredPath)
	require.NoError(t, quarantineRetiredTemplate(root, retiredPath, quarantinePath))
	require.NoError(t, root.WriteFile(retiredPath, replacementContents, 0644))

	disposition, err := cleanupQuarantinedTemplate(root, retiredPath, quarantinePath, templateDigest(releaseContents))
	require.NoError(t, err)
	require.Equal(t, retainTemplateOwnership, disposition, "the prior ownership entry must survive until the replacement is classified")
	contents, err := root.ReadFile(retiredPath)
	require.NoError(t, err)
	require.Equal(t, replacementContents, contents)
	_, err = root.Stat(quarantinePath)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestCleanupQuarantinedTemplateRetainsOwnershipOnRestoreFailure(t *testing.T) {
	templatesDir := t.TempDir()
	root, err := os.OpenRoot(templatesDir)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, root.Close()) })

	retiredPath := "retired.yaml"
	releaseContents := []byte("release contents")
	modifiedContents := []byte("locally modified contents")
	replacementContents := []byte("concurrent user replacement")
	quarantinePath := retiredTemplateQuarantinePath(retiredPath)
	require.NoError(t, root.WriteFile(quarantinePath, modifiedContents, 0644))
	require.NoError(t, root.WriteFile(retiredPath, replacementContents, 0644))

	disposition, err := cleanupQuarantinedTemplate(root, retiredPath, quarantinePath, templateDigest(releaseContents))
	require.Error(t, err)
	require.Equal(t, retainTemplateOwnership, disposition, "failed recovery must retain the prior ownership entry for retry")
	contents, readErr := root.ReadFile(retiredPath)
	require.NoError(t, readErr)
	require.Equal(t, replacementContents, contents)
	contents, readErr = root.ReadFile(quarantinePath)
	require.NoError(t, readErr)
	require.Equal(t, modifiedContents, contents)
}

func TestCreateTemplateDirectoriesReportsParentsOnRetry(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, root.Close()) })

	expectedParents := []string{".", "first"}
	for range 2 {
		parentsToSync, err := createTemplateDirectories(root, filepath.Join("first", "second"))
		require.NoError(t, err)
		require.ElementsMatch(t, expectedParents, parentsToSync)
	}
}

func TestRestoreQuarantinedTemplateCompletesInterruptedRestore(t *testing.T) {
	testCases := []struct {
		name    string
		restore func(t *testing.T, root *os.Root, quarantinePath, retiredPath string, contents []byte)
	}{
		{
			name: "hard link",
			restore: func(t *testing.T, root *os.Root, quarantinePath, retiredPath string, _ []byte) {
				require.NoError(t, root.Link(quarantinePath, retiredPath))
			},
		},
		{
			name: "copied file",
			restore: func(t *testing.T, root *os.Root, _ string, retiredPath string, contents []byte) {
				token := strings.Repeat("a", 32)
				temporaryPath := templateRestoreTemporaryPath(retiredPath) + "-" + token
				require.NoError(t, root.WriteFile(temporaryPath, contents, 0o644))
				require.NoError(t, root.Link(temporaryPath, retiredPath))
				require.NoError(t, root.WriteFile(templateRestoreStatePrefix(retiredPath)+token, []byte("copy\n"+templateDigest(contents)), 0o600))
			},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			templatesDir := t.TempDir()
			root, err := os.OpenRoot(templatesDir)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, root.Close()) })

			retiredPath := "retired.yaml"
			quarantinePath := retiredTemplateQuarantinePath(retiredPath)
			contents := []byte("locally modified contents")
			require.NoError(t, root.WriteFile(quarantinePath, contents, 0644))
			testCase.restore(t, root, quarantinePath, retiredPath, contents)

			require.NoError(t, restoreQuarantinedTemplate(root, retiredPath, quarantinePath))
			restored, err := root.ReadFile(retiredPath)
			require.NoError(t, err)
			require.Equal(t, contents, restored)
			_, err = root.Lstat(quarantinePath)
			require.ErrorIs(t, err, os.ErrNotExist)
		})
	}
}

func TestFinishInterruptedTemplateRestoreSyncsCopiedFile(t *testing.T) {
	testCases := []struct {
		name              string
		copyRestore       bool
		expectedSyncCalls int
	}{
		{name: "hard link", expectedSyncCalls: 0},
		{name: "copied file", copyRestore: true, expectedSyncCalls: 1},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			root, err := os.OpenRoot(t.TempDir())
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, root.Close()) })

			retiredPath := "retired.yaml"
			quarantinePath := retiredTemplateQuarantinePath(retiredPath)
			contents := []byte("locally modified contents")
			require.NoError(t, root.WriteFile(quarantinePath, contents, 0o644))
			quarantineInfo, err := root.Stat(quarantinePath)
			require.NoError(t, err)
			if testCase.copyRestore {
				token := strings.Repeat("a", 32)
				temporaryPath := templateRestoreTemporaryPath(retiredPath) + "-" + token
				require.NoError(t, root.WriteFile(temporaryPath, contents, 0o644))
				require.NoError(t, root.Link(temporaryPath, retiredPath))
				require.NoError(t, root.WriteFile(templateRestoreStatePrefix(retiredPath)+token, []byte("copy\n"+templateDigest(contents)), 0o600))
			} else {
				require.NoError(t, root.Link(quarantinePath, retiredPath))
			}

			syncCalls := 0
			completed, err := finishInterruptedTemplateRestore(root, retiredPath, quarantinePath, func(_ *os.Root, _ string, mode os.FileMode) error {
				syncCalls++
				require.Equal(t, quarantineInfo.Mode().Perm(), mode.Perm())
				return nil
			})
			require.NoError(t, err)
			require.True(t, completed)
			require.Equal(t, testCase.expectedSyncCalls, syncCalls)
			if testCase.copyRestore {
				_, err = root.Lstat(templateRestoreTemporaryPath(retiredPath) + "-" + strings.Repeat("a", 32))
				require.ErrorIs(t, err, os.ErrNotExist)
			}
		})
	}
}

func TestRecoverTemplateOwnershipCleansCommittedCopyState(t *testing.T) {
	templatesDir := t.TempDir()
	retiredPath := "retired.yaml"
	contents := []byte("locally modified contents")
	require.NoError(t, os.WriteFile(filepath.Join(templatesDir, retiredPath), contents, 0o644))
	seedTemplateOwnership(t, templatesDir, filepath.Join(templatesDir, retiredPath))

	root, err := os.OpenRoot(templatesDir)
	require.NoError(t, err)
	token := strings.Repeat("a", 32)
	temporaryPath := templateRestoreTemporaryPath(retiredPath) + "-" + token
	statePath := templateRestoreStatePrefix(retiredPath) + token
	require.NoError(t, root.Link(retiredPath, temporaryPath))
	require.NoError(t, root.WriteFile(statePath, []byte("copy\n"+templateDigest(contents)), 0o600))
	require.NoError(t, root.Close())

	require.NoError(t, recoverTemplateOwnership(templatesDir))
	require.FileExists(t, filepath.Join(templatesDir, retiredPath))
	require.NoFileExists(t, filepath.Join(templatesDir, temporaryPath))
	require.NoFileExists(t, filepath.Join(templatesDir, statePath))
}

func TestRecoverTemplateOwnershipResolvesPublishedCopyState(t *testing.T) {
	t.Run("finishes matching published copy", func(t *testing.T) {
		templatesDir := t.TempDir()
		retiredPath := "retired.yaml"
		releaseContents := []byte("release contents")
		localContents := []byte("locally modified contents")
		require.NoError(t, os.WriteFile(filepath.Join(templatesDir, retiredPath), releaseContents, 0o644))
		seedTemplateOwnership(t, templatesDir, filepath.Join(templatesDir, retiredPath))

		root, err := os.OpenRoot(templatesDir)
		require.NoError(t, err)
		quarantinePath := retiredTemplateQuarantinePath(retiredPath)
		require.NoError(t, root.WriteFile(quarantinePath, localContents, 0o644))
		require.NoError(t, root.WriteFile(retiredPath, localContents, 0o644))
		token := strings.Repeat("a", 32)
		temporaryPath := templateRestoreTemporaryPath(retiredPath) + "-" + token
		statePath := templateRestoreStatePrefix(retiredPath) + token
		require.NoError(t, root.Link(retiredPath, temporaryPath))
		require.NoError(t, root.WriteFile(statePath, []byte("copy\n"+templateDigest(localContents)), 0o600))
		require.NoError(t, root.Close())

		require.NoError(t, recoverTemplateOwnership(templatesDir))
		contents, err := os.ReadFile(filepath.Join(templatesDir, retiredPath))
		require.NoError(t, err)
		require.Equal(t, localContents, contents)
		require.NoFileExists(t, filepath.Join(templatesDir, quarantinePath))
		require.NoFileExists(t, filepath.Join(templatesDir, temporaryPath))
		require.NoFileExists(t, filepath.Join(templatesDir, statePath))
	})

	t.Run("rolls back stale copy and retries current quarantine", func(t *testing.T) {
		templatesDir := t.TempDir()
		retiredPath := "retired.yaml"
		releaseContents := []byte("release contents")
		staleContents := []byte("stale local contents")
		currentContents := []byte("current local contents")
		require.NoError(t, os.WriteFile(filepath.Join(templatesDir, retiredPath), releaseContents, 0o644))
		seedTemplateOwnership(t, templatesDir, filepath.Join(templatesDir, retiredPath))

		root, err := os.OpenRoot(templatesDir)
		require.NoError(t, err)
		quarantinePath := retiredTemplateQuarantinePath(retiredPath)
		require.NoError(t, root.WriteFile(quarantinePath, currentContents, 0o644))
		require.NoError(t, root.WriteFile(retiredPath, staleContents, 0o644))
		token := strings.Repeat("a", 32)
		temporaryPath := templateRestoreTemporaryPath(retiredPath) + "-" + token
		statePath := templateRestoreStatePrefix(retiredPath) + token
		require.NoError(t, root.Link(retiredPath, temporaryPath))
		require.NoError(t, root.WriteFile(statePath, []byte("copy\n"+templateDigest(staleContents)), 0o600))
		require.NoError(t, root.Close())

		require.NoError(t, recoverTemplateOwnership(templatesDir))
		contents, err := os.ReadFile(filepath.Join(templatesDir, retiredPath))
		require.NoError(t, err)
		require.Equal(t, currentContents, contents)
		require.NoFileExists(t, filepath.Join(templatesDir, quarantinePath))
		require.NoFileExists(t, filepath.Join(templatesDir, temporaryPath))
		require.NoFileExists(t, filepath.Join(templatesDir, statePath))
	})

	t.Run("preserves unrelated replacement", func(t *testing.T) {
		templatesDir := t.TempDir()
		retiredPath := "retired.yaml"
		releaseContents := []byte("release contents")
		staleContents := []byte("stale local contents")
		currentContents := []byte("current local contents")
		replacementContents := []byte("unrelated replacement")
		require.NoError(t, os.WriteFile(filepath.Join(templatesDir, retiredPath), releaseContents, 0o644))
		seedTemplateOwnership(t, templatesDir, filepath.Join(templatesDir, retiredPath))

		root, err := os.OpenRoot(templatesDir)
		require.NoError(t, err)
		quarantinePath := retiredTemplateQuarantinePath(retiredPath)
		require.NoError(t, root.WriteFile(quarantinePath, currentContents, 0o644))
		require.NoError(t, root.WriteFile(retiredPath, replacementContents, 0o644))
		token := strings.Repeat("a", 32)
		statePath := templateRestoreStatePrefix(retiredPath) + token
		require.NoError(t, root.WriteFile(statePath, []byte("copy\n"+templateDigest(staleContents)), 0o600))
		require.NoError(t, root.Close())

		err = recoverTemplateOwnership(templatesDir)
		require.Error(t, err)
		contents, readErr := os.ReadFile(filepath.Join(templatesDir, retiredPath))
		require.NoError(t, readErr)
		require.Equal(t, replacementContents, contents)
		require.FileExists(t, filepath.Join(templatesDir, quarantinePath))
		require.FileExists(t, filepath.Join(templatesDir, statePath))
	})

	t.Run("preserves a published copy mutated after publication", func(t *testing.T) {
		templatesDir := t.TempDir()
		retiredPath := "retired.yaml"
		releaseContents := []byte("release contents")
		publishedContents := []byte("published local contents")
		currentContents := []byte("current quarantine contents")
		lateContents := []byte("late destination edit")
		require.NoError(t, os.WriteFile(filepath.Join(templatesDir, retiredPath), releaseContents, 0o644))
		seedTemplateOwnership(t, templatesDir, filepath.Join(templatesDir, retiredPath))

		root, err := os.OpenRoot(templatesDir)
		require.NoError(t, err)
		quarantinePath := retiredTemplateQuarantinePath(retiredPath)
		require.NoError(t, root.WriteFile(quarantinePath, currentContents, 0o644))
		require.NoError(t, root.WriteFile(retiredPath, publishedContents, 0o644))
		token := strings.Repeat("a", 32)
		temporaryPath := templateRestoreTemporaryPath(retiredPath) + "-" + token
		statePath := templateRestoreStatePrefix(retiredPath) + token
		require.NoError(t, root.Link(retiredPath, temporaryPath))
		require.NoError(t, root.WriteFile(statePath, []byte("copy\n"+templateDigest(publishedContents)), 0o600))
		require.NoError(t, root.WriteFile(retiredPath, lateContents, 0o644))
		require.NoError(t, root.Close())

		err = recoverTemplateOwnership(templatesDir)
		require.Error(t, err)
		contents, readErr := os.ReadFile(filepath.Join(templatesDir, retiredPath))
		require.NoError(t, readErr)
		require.Equal(t, lateContents, contents)
		require.FileExists(t, filepath.Join(templatesDir, quarantinePath))
		require.FileExists(t, filepath.Join(templatesDir, temporaryPath))
		require.FileExists(t, filepath.Join(templatesDir, statePath))
	})
}

func TestRecoverTemplateOwnershipFinishesMovedStateAfterLateWrite(t *testing.T) {
	templatesDir := t.TempDir()
	retiredPath := "retired.yaml"
	releaseContents := []byte("release contents")
	localContents := []byte("locally modified contents")
	lateContents := []byte("late local write")
	require.NoError(t, os.WriteFile(filepath.Join(templatesDir, retiredPath), releaseContents, 0o644))
	seedTemplateOwnership(t, templatesDir, filepath.Join(templatesDir, retiredPath))
	require.NoError(t, os.WriteFile(filepath.Join(templatesDir, retiredPath), localContents, 0o644))

	root, err := os.OpenRoot(templatesDir)
	require.NoError(t, err)
	quarantinePath := retiredTemplateQuarantinePath(retiredPath)
	require.NoError(t, quarantineRetiredTemplate(root, retiredPath, quarantinePath))
	state, err := newTemplateRestoreState(retiredPath)
	require.NoError(t, err)
	state.kind = templateRestoreMove
	state.digest = templateDigest(localContents)
	require.NoError(t, createTemplateRestoreState(root, state))
	openQuarantine, err := root.OpenFile(quarantinePath, os.O_RDWR, 0)
	require.NoError(t, err)
	require.NoError(t, renameTemplateRestoreNoReplace(root, quarantinePath, retiredPath))
	require.NoError(t, openQuarantine.Truncate(0))
	_, err = openQuarantine.WriteAt(lateContents, 0)
	require.NoError(t, err)
	require.NoError(t, openQuarantine.Close())
	require.NoError(t, root.Close())

	require.NoError(t, recoverTemplateOwnership(templatesDir))
	contents, err := os.ReadFile(filepath.Join(templatesDir, retiredPath))
	require.NoError(t, err)
	require.Equal(t, lateContents, contents)
	require.NoFileExists(t, filepath.Join(templatesDir, state.statePath))
}

func TestRestoreQuarantinedTemplatePreservesEqualContentReplacement(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, root.Close()) })

	retiredPath := "retired.yaml"
	quarantinePath := retiredTemplateQuarantinePath(retiredPath)
	contents := []byte("same contents")
	require.NoError(t, root.WriteFile(quarantinePath, contents, 0o644))
	require.NoError(t, root.WriteFile(retiredPath, contents, 0o600))
	beforeInfo, err := root.Stat(retiredPath)
	require.NoError(t, err)

	err = restoreQuarantinedTemplate(root, retiredPath, quarantinePath)
	require.Error(t, err)
	restoredInfo, statErr := root.Stat(retiredPath)
	require.NoError(t, statErr)
	require.Equal(t, beforeInfo.Mode().Perm(), restoredInfo.Mode().Perm())
	restoredContents, readErr := root.ReadFile(retiredPath)
	require.NoError(t, readErr)
	require.Equal(t, contents, restoredContents)
	quarantinedContents, readErr := root.ReadFile(quarantinePath)
	require.NoError(t, readErr)
	require.Equal(t, contents, quarantinedContents)
}

func TestRecoverTemplateOwnershipRestoresInterruptedQuarantine(t *testing.T) {
	templatesDir := t.TempDir()
	retiredPath := filepath.Join(templatesDir, "retired.yaml")
	releaseContents := []byte("release contents")
	modifiedContents := []byte("locally modified contents")
	require.NoError(t, os.WriteFile(retiredPath, releaseContents, 0644))
	seedTemplateOwnership(t, templatesDir, retiredPath)
	require.NoError(t, os.WriteFile(retiredPath, modifiedContents, 0644))

	root, err := os.OpenRoot(templatesDir)
	require.NoError(t, err)
	quarantinePath := retiredTemplateQuarantinePath("retired.yaml")
	require.NoError(t, quarantineRetiredTemplate(root, "retired.yaml", quarantinePath))
	require.NoError(t, root.Close())

	require.NoError(t, recoverTemplateOwnership(templatesDir))
	contents, err := os.ReadFile(retiredPath)
	require.NoError(t, err)
	require.Equal(t, modifiedContents, contents)
	require.NoFileExists(t, filepath.Join(templatesDir, quarantinePath))

	require.NoError(t, reconcileTemplateOwnership(templatesDir, newWrittenTemplates(t)))
	contents, err = os.ReadFile(retiredPath)
	require.NoError(t, err)
	require.Equal(t, modifiedContents, contents)
}

func TestRecoverTemplateOwnershipBeforeReintroducedPath(t *testing.T) {
	templatesDir := t.TempDir()
	relativePath := filepath.Join("nested", "deeper", "retired.yaml")
	retiredPath := filepath.Join(templatesDir, relativePath)
	releaseContents := []byte("release contents")
	modifiedContents := []byte("locally modified contents")
	require.NoError(t, os.MkdirAll(filepath.Dir(retiredPath), 0755))
	require.NoError(t, os.WriteFile(retiredPath, releaseContents, 0644))
	seedTemplateOwnership(t, templatesDir, retiredPath)
	require.NoError(t, os.WriteFile(retiredPath, modifiedContents, 0644))

	root, err := os.OpenRoot(templatesDir)
	require.NoError(t, err)
	quarantinePath := retiredTemplateQuarantinePath(filepath.ToSlash(relativePath))
	require.NoError(t, quarantineRetiredTemplate(root, relativePath, quarantinePath))
	require.NoError(t, root.Close())
	require.NoError(t, os.RemoveAll(filepath.Join(templatesDir, "nested")), "simulate an interrupted cleanup that purged multiple parent levels")

	// Recovery runs before a new release can write a reintroduced retiredPath.
	require.NoError(t, recoverTemplateOwnership(templatesDir))
	contents, err := os.ReadFile(retiredPath)
	require.NoError(t, err)
	require.Equal(t, modifiedContents, contents)
	require.NoFileExists(t, filepath.Join(templatesDir, quarantinePath))
}

func TestRecoverTemplateOwnershipRejectsUnknownQuarantine(t *testing.T) {
	templatesDir := t.TempDir()
	require.NoError(t, writeTemplateOwnership(templatesDir, &templateOwnershipManifest{
		Version: templateOwnershipVersion,
		Files:   map[string]string{},
	}))
	require.NoError(t, os.WriteFile(filepath.Join(templatesDir, templateOwnershipRetiredPrefix+"unknown"), []byte("unknown"), 0600))

	err := recoverTemplateOwnership(templatesDir)
	require.ErrorContains(t, err, "unrecognized template ownership quarantine")
}

func TestUpdateIfOutdatedRecoversSameVersionQuarantine(t *testing.T) {
	templatesDir := t.TempDir()
	retiredPath := filepath.Join(templatesDir, "retired.yaml")
	releaseContents := []byte("release contents")
	modifiedContents := []byte("locally modified contents")
	require.NoError(t, os.WriteFile(retiredPath, releaseContents, 0644))
	seedTemplateOwnership(t, templatesDir, retiredPath)
	require.NoError(t, os.WriteFile(retiredPath, modifiedContents, 0644))

	root, err := os.OpenRoot(templatesDir)
	require.NoError(t, err)
	quarantinePath := retiredTemplateQuarantinePath("retired.yaml")
	require.NoError(t, quarantineRetiredTemplate(root, "retired.yaml", quarantinePath))
	require.NoError(t, root.Close())

	previousConfig := config.DefaultConfig
	cfg := &config.Config{
		TemplateVersion:              "v1.0.0",
		LatestNucleiTemplatesVersion: "v1.0.0",
		Logger:                       gologger.DefaultLogger,
	}
	cfg.SetTemplatesDir(templatesDir)
	config.DefaultConfig = cfg
	t.Cleanup(func() { config.DefaultConfig = previousConfig })

	tm := &TemplateManager{}
	require.NoError(t, tm.UpdateIfOutdated())
	contents, err := os.ReadFile(retiredPath)
	require.NoError(t, err)
	require.Equal(t, modifiedContents, contents)
	require.NoFileExists(t, filepath.Join(templatesDir, quarantinePath))
}

func TestCopyQuarantinedTemplate(t *testing.T) {
	t.Run("restores without overwriting", func(t *testing.T) {
		templatesDir := t.TempDir()
		root, err := os.OpenRoot(templatesDir)
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, root.Close()) })

		quarantinePath := templateOwnershipRetiredPrefix + "test"
		contents := []byte("locally modified contents")
		require.NoError(t, root.WriteFile(quarantinePath, contents, 0644))
		err = copyQuarantinedTemplate(root, "retired.yaml", quarantinePath)
		require.NoError(t, err)
		restoredContents, err := root.ReadFile("retired.yaml")
		require.NoError(t, err)
		require.Equal(t, contents, restoredContents)
		_, err = root.Stat(quarantinePath)
		require.ErrorIs(t, err, os.ErrNotExist)
	})

	t.Run("bypasses an incomplete temporary copy", func(t *testing.T) {
		templatesDir := t.TempDir()
		root, err := os.OpenRoot(templatesDir)
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, root.Close()) })

		retiredPath := filepath.Join("nested", "retired.yaml")
		quarantinePath := templateOwnershipRetiredPrefix + "interrupted-copy"
		contents := []byte("locally modified contents")
		require.NoError(t, root.WriteFile(quarantinePath, contents, 0o644))
		require.NoError(t, root.MkdirAll(filepath.Dir(retiredPath), 0o755))
		temporaryPath := templateRestoreTemporaryPath(retiredPath) + "-partial"
		require.NoError(t, root.WriteFile(temporaryPath, []byte("partial"), 0o600))

		require.NoError(t, copyQuarantinedTemplate(root, retiredPath, quarantinePath))
		restoredContents, err := root.ReadFile(retiredPath)
		require.NoError(t, err)
		require.Equal(t, contents, restoredContents)
		partialContents, err := root.ReadFile(temporaryPath)
		require.NoError(t, err)
		require.Equal(t, []byte("partial"), partialContents)
		_, err = root.Lstat(quarantinePath)
		require.ErrorIs(t, err, os.ErrNotExist)
	})

	t.Run("preserves an unknown temporary-named file", func(t *testing.T) {
		templatesDir := t.TempDir()
		root, err := os.OpenRoot(templatesDir)
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, root.Close()) })

		retiredPath := filepath.Join("nested", "retired.yaml")
		quarantinePath := templateOwnershipRetiredPrefix + "unknown-temporary"
		quarantinedContents := []byte("locally modified contents")
		sentinelContents := []byte("unrelated local file")
		require.NoError(t, root.WriteFile(quarantinePath, quarantinedContents, 0o644))
		require.NoError(t, root.MkdirAll(filepath.Dir(retiredPath), 0o755))
		sentinelPath := templateRestoreTemporaryPath(retiredPath)
		require.NoError(t, root.WriteFile(sentinelPath, sentinelContents, 0o600))

		require.NoError(t, copyQuarantinedTemplate(root, retiredPath, quarantinePath))
		contents, err := root.ReadFile(retiredPath)
		require.NoError(t, err)
		require.Equal(t, quarantinedContents, contents)
		contents, err = root.ReadFile(sentinelPath)
		require.NoError(t, err)
		require.Equal(t, sentinelContents, contents)
	})

	t.Run("preserves a concurrent replacement", func(t *testing.T) {
		templatesDir := t.TempDir()
		root, err := os.OpenRoot(templatesDir)
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, root.Close()) })

		quarantinePath := templateOwnershipRetiredPrefix + "test"
		quarantinedContents := []byte("locally modified contents")
		replacementContents := []byte("concurrent replacement")
		require.NoError(t, root.WriteFile(quarantinePath, quarantinedContents, 0644))
		require.NoError(t, root.WriteFile("retired.yaml", replacementContents, 0644))
		err = copyQuarantinedTemplate(root, "retired.yaml", quarantinePath)
		require.Error(t, err)
		contents, readErr := root.ReadFile("retired.yaml")
		require.NoError(t, readErr)
		require.Equal(t, replacementContents, contents)
		contents, readErr = root.ReadFile(quarantinePath)
		require.NoError(t, readErr)
		require.Equal(t, quarantinedContents, contents)
	})
}

func TestWriteTemplateOwnershipReplacesManifest(t *testing.T) {
	templatesDir := t.TempDir()
	first := &templateOwnershipManifest{
		Version: templateOwnershipVersion,
		Files:   map[string]string{"first.yaml": strings.Repeat("0", 64)},
	}
	second := &templateOwnershipManifest{
		Version: templateOwnershipVersion,
		Files:   map[string]string{"second.yaml": strings.Repeat("1", 64)},
	}
	require.NoError(t, writeTemplateOwnership(templatesDir, first))
	require.NoError(t, writeTemplateOwnership(templatesDir, second))

	loaded, err := loadTemplateOwnership(templatesDir)
	require.NoError(t, err)
	require.Equal(t, second, loaded)
	temporaryFiles, err := filepath.Glob(filepath.Join(templatesDir, templateOwnershipFileName+".tmp-*"))
	require.NoError(t, err)
	require.Empty(t, temporaryFiles)
}

func TestLoadTemplateOwnershipRejectsNonRegularManifest(t *testing.T) {
	templatesDir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(templatesDir, templateOwnershipFileName), 0755))
	_, err := loadTemplateOwnership(templatesDir)
	require.ErrorContains(t, err, "is not a regular file")
}

func TestReconcileTemplateOwnership(t *testing.T) {
	t.Run("removes unchanged retired owned templates", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create subdirectories for templates
		templatesDir1 := filepath.Join(tmpDir, "cves", "2023")
		templatesDir2 := filepath.Join(tmpDir, "exposures", "configs")
		require.NoError(t, os.MkdirAll(templatesDir1, 0755))
		require.NoError(t, os.MkdirAll(templatesDir2, 0755))

		// Create template files
		template1 := filepath.Join(templatesDir1, "CVE-2023-1234.yaml")
		template2 := filepath.Join(templatesDir1, "CVE-2023-5678.yaml")
		template3 := filepath.Join(templatesDir2, "git-config-exposure.yaml")
		retiredTemplate1 := filepath.Join(templatesDir1, "old-template.yaml")
		retiredTemplate2 := filepath.Join(templatesDir2, "removed-template.yaml")

		// Write valid template files
		templateContent := `id: test-template
info:
  name: Test Template
  author: test
  severity: info`
		require.NoError(t, os.WriteFile(template1, []byte(templateContent), 0644))
		require.NoError(t, os.WriteFile(template2, []byte(templateContent), 0644))
		require.NoError(t, os.WriteFile(template3, []byte(templateContent), 0644))
		require.NoError(t, os.WriteFile(retiredTemplate1, []byte(templateContent), 0644))
		require.NoError(t, os.WriteFile(retiredTemplate2, []byte(templateContent), 0644))
		seedTemplateOwnership(t, tmpDir, template1, template2, template3, retiredTemplate1, retiredTemplate2)

		// The current release still owns only template1, template2, and template3.
		absTemplate1, _ := filepath.Abs(template1)
		absTemplate2, _ := filepath.Abs(template2)
		absTemplate3, _ := filepath.Abs(template3)
		// Normalize paths consistently with ownership reconciliation.
		absTemplate1 = filepath.Clean(absTemplate1)
		absTemplate2 = filepath.Clean(absTemplate2)
		absTemplate3 = filepath.Clean(absTemplate3)
		writtenTemplates := newWrittenTemplates(t, absTemplate1, absTemplate2, absTemplate3)

		// Reconcile previous ownership with the current release.
		err := reconcileTemplateOwnership(tmpDir, writtenTemplates)
		require.NoError(t, err)

		// Unchanged templates retired by the current release are removed.
		require.NoFileExists(t, retiredTemplate1, "retired owned template should be removed")
		require.NoFileExists(t, retiredTemplate2, "retired owned template should be removed")

		// Templates owned by the current release remain in place.
		require.FileExists(t, template1, "template from new release should exist")
		require.FileExists(t, template2, "template from new release should exist")
		require.FileExists(t, template3, "template from new release should exist")
	})

	t.Run("preserves unowned templates in custom directories", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create custom template directory
		customGitHubDir := filepath.Join(tmpDir, "github", "owner", "repo")
		require.NoError(t, os.MkdirAll(customGitHubDir, 0755))

		// Create custom template file
		customTemplate := filepath.Join(customGitHubDir, "custom-template.yaml")
		templateContent := `id: custom-template
info:
  name: Custom Template
  author: test
  severity: info`
		require.NoError(t, os.WriteFile(customTemplate, []byte(templateContent), 0644))

		// The custom template was never recorded as release-owned.
		writtenTemplates := newWrittenTemplates(t)

		// Reconciliation must not infer ownership by scanning the tree.
		err := reconcileTemplateOwnership(tmpDir, writtenTemplates)
		require.NoError(t, err)

		// Verify custom template was NOT removed
		require.FileExists(t, customTemplate, "custom template should be preserved")
	})

	t.Run("preserves locally saved custom templates", func(t *testing.T) {
		templatesDir := t.TempDir()

		officialTemplate := filepath.Join(templatesDir, "http", "official.yaml")
		localTemplate := filepath.Join(templatesDir, "my-custom-template.yaml")
		require.NoError(t, os.MkdirAll(filepath.Dir(officialTemplate), 0755))
		require.NoError(t, os.WriteFile(officialTemplate, []byte(`id: official-template
info:
  name: Official Template
  author: projectdiscovery
  severity: info`), 0644))
		require.NoError(t, os.WriteFile(localTemplate, []byte(`id: my-custom-template
info:
  name: My Custom Template
  author: local
  severity: info`), 0644))

		writtenTemplates := newWrittenTemplates(t, officialTemplate)

		err := reconcileTemplateOwnership(templatesDir, writtenTemplates)
		require.NoError(t, err)
		require.NoError(t, reconcileTemplateOwnership(templatesDir, writtenTemplates), "custom template should survive subsequent updates after ownership is recorded")
		require.FileExists(t, officialTemplate, "template from the new release should be preserved")
		require.FileExists(t, localTemplate, "locally saved custom template should be preserved")
	})

	t.Run("preserves locally modified retired templates", func(t *testing.T) {
		templatesDir := t.TempDir()

		retiredTemplate := filepath.Join(templatesDir, "retired.yaml")
		require.NoError(t, os.WriteFile(retiredTemplate, []byte("original release contents"), 0644))
		seedTemplateOwnership(t, templatesDir, retiredTemplate)
		require.NoError(t, os.WriteFile(retiredTemplate, []byte("locally modified contents"), 0644))

		writtenTemplates := newWrittenTemplates(t)
		require.NoError(t, reconcileTemplateOwnership(templatesDir, writtenTemplates))
		contents, err := os.ReadFile(retiredTemplate)
		require.NoError(t, err)
		require.Equal(t, "locally modified contents", string(contents), "locally modified retired template should be preserved unchanged")
	})

	t.Run("does not follow retired template symlinks outside the templates directory", func(t *testing.T) {
		templatesDir := t.TempDir()
		externalDir := t.TempDir()
		retiredDir := filepath.Join(templatesDir, "retired")
		retiredTemplate := filepath.Join(retiredDir, "official.yaml")
		contents := []byte("original release contents")

		require.NoError(t, os.Mkdir(retiredDir, 0755))
		require.NoError(t, os.WriteFile(retiredTemplate, contents, 0644))
		seedTemplateOwnership(t, templatesDir, retiredTemplate)
		require.NoError(t, os.Remove(retiredTemplate))
		require.NoError(t, os.Remove(retiredDir))

		externalTemplate := filepath.Join(externalDir, "official.yaml")
		require.NoError(t, os.WriteFile(externalTemplate, contents, 0644))
		if err := os.Symlink(externalDir, retiredDir); err != nil {
			t.Skipf("symlinks are unavailable: %v", err)
		}

		writtenTemplates := newWrittenTemplates(t)
		require.NoError(t, reconcileTemplateOwnership(templatesDir, writtenTemplates))
		require.FileExists(t, externalTemplate, "ownership cleanup must remain confined to the templates directory")
	})

	t.Run("rejects ownership paths outside the templates directory", func(t *testing.T) {
		parentDir := t.TempDir()
		templatesDir := filepath.Join(parentDir, "templates")
		require.NoError(t, os.Mkdir(templatesDir, 0755))
		externalTemplate := filepath.Join(parentDir, "outside.yaml")
		require.NoError(t, os.WriteFile(externalTemplate, []byte("external contents"), 0644))

		invalidManifest := `{"version":1,"files":{"../outside.yaml":"` + strings.Repeat("0", 64) + `"}}`
		require.NoError(t, os.WriteFile(filepath.Join(templatesDir, templateOwnershipFileName), []byte(invalidManifest), 0600))

		writtenTemplates := newWrittenTemplates(t)
		require.NoError(t, reconcileTemplateOwnership(templatesDir, writtenTemplates))
		require.FileExists(t, externalTemplate, "invalid ownership metadata must not authorize deletion")
		manifest, err := loadTemplateOwnership(templatesDir)
		require.NoError(t, err)
		require.Empty(t, manifest.Files, "invalid ownership metadata should be replaced with current release ownership")
	})

	t.Run("removes retired owned templates next to custom directories", func(t *testing.T) {
		tmpDir := t.TempDir()

		customGitHubDir := filepath.Join(tmpDir, "github", "owner", "repo")
		require.NoError(t, os.MkdirAll(customGitHubDir, 0755))
		customTemplate := filepath.Join(customGitHubDir, "custom-template.yaml")
		require.NoError(t, os.WriteFile(customTemplate, []byte(`id: custom-template
info:
  name: Custom Template
  author: test
  severity: info`), 0644))

		siblingDir := filepath.Join(tmpDir, "github-evil")
		require.NoError(t, os.MkdirAll(siblingDir, 0755))
		siblingTemplate := filepath.Join(siblingDir, "retired-template.yaml")
		require.NoError(t, os.WriteFile(siblingTemplate, []byte(`id: retired-template
info:
  name: Retired Template
  author: test
  severity: info`), 0644))
		seedTemplateOwnership(t, tmpDir, siblingTemplate)

		writtenTemplates := newWrittenTemplates(t)

		err := reconcileTemplateOwnership(tmpDir, writtenTemplates)
		require.NoError(t, err)

		require.FileExists(t, customTemplate, "custom template should be preserved")
		require.NoFileExists(t, siblingTemplate, "custom directory sibling prefix should not be preserved")
	})

	t.Run("preserves unowned non-template files", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create non-template files
		readmeFile := filepath.Join(tmpDir, "README.md")
		configFile := filepath.Join(tmpDir, "cves.json")
		checksumFile := filepath.Join(tmpDir, ".checksum")

		require.NoError(t, os.WriteFile(readmeFile, []byte("# Templates"), 0644))
		require.NoError(t, os.WriteFile(configFile, []byte("{}"), 0644))
		require.NoError(t, os.WriteFile(checksumFile, []byte(""), 0644))

		// No file was recorded as release-owned.
		writtenTemplates := newWrittenTemplates(t)

		// Reconciliation preserves every unowned file.
		err := reconcileTemplateOwnership(tmpDir, writtenTemplates)
		require.NoError(t, err)

		// Verify non-template files were NOT removed
		require.FileExists(t, readmeFile, "README.md should be preserved")
		require.FileExists(t, configFile, "config file should be preserved")
		require.FileExists(t, checksumFile, "checksum file should be preserved")
	})

	t.Run("removes owned templates when the current release is empty", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create template files
		template1 := filepath.Join(tmpDir, "template1.yaml")
		templateContent := `id: test-template
info:
  name: Test Template
  author: test
  severity: info`
		require.NoError(t, os.WriteFile(template1, []byte(templateContent), 0644))
		seedTemplateOwnership(t, tmpDir, template1)

		// The current release contains no templates.
		writtenTemplates := newWrittenTemplates(t)

		// Reconciliation removes the unchanged template owned by the prior release.
		err := reconcileTemplateOwnership(tmpDir, writtenTemplates)
		require.NoError(t, err)

		// The prior owned template is absent from the current release.
		require.NoFileExists(t, template1, "template retired by the current release should be removed")
	})

	t.Run("accepts absolute written template paths", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create template file
		template1 := filepath.Join(tmpDir, "template1.yaml")
		templateContent := `id: test-template
info:
  name: Test Template
  author: test
  severity: info`
		require.NoError(t, os.WriteFile(template1, []byte(templateContent), 0644))

		writtenTemplates := newWrittenTemplates(t, template1)

		// Reconciliation normalizes the absolute path into the relative manifest key.
		err := reconcileTemplateOwnership(tmpDir, writtenTemplates)
		require.NoError(t, err)

		// The current release retains ownership of the template.
		require.FileExists(t, template1, "template owned by the current release should be preserved")
	})
}

func TestReconcileTemplateOwnershipDirectoryValidation(t *testing.T) {
	t.Run("handles empty templates directory", func(t *testing.T) {
		// Create temporary directories
		tmpDir, err := os.MkdirTemp("", "nuclei-cleanup-empty-dir-test-*")
		require.NoError(t, err)
		defer func() {
			_ = os.RemoveAll(tmpDir)
		}()

		cfgdir, err := os.MkdirTemp("", "nuclei-config-*")
		require.NoError(t, err)
		defer func() {
			_ = os.RemoveAll(cfgdir)
		}()

		config.DefaultConfig.SetConfigDir(cfgdir)
		config.DefaultConfig.SetTemplatesDir(tmpDir)

		// Directory exists but is empty (user deleted all templates)
		require.True(t, fileutil.FolderExists(tmpDir), "templates directory should exist")

		// The current release contains no templates.
		writtenTemplates := newWrittenTemplates(t)

		// Reconciliation accepts an existing empty templates directory.
		err = reconcileTemplateOwnership(tmpDir, writtenTemplates)
		require.NoError(t, err, "reconciliation should accept an empty templates directory")

		// Reconciliation does not remove the templates directory itself.
		require.True(t, fileutil.FolderExists(tmpDir), "templates directory should still exist")
	})

	t.Run("rejects non-existent templates directory", func(t *testing.T) {
		nonExistentDir := filepath.Join(t.TempDir(), "missing")
		require.False(t, fileutil.FolderExists(nonExistentDir), "directory should not exist")

		writtenTemplates := newWrittenTemplates(t)

		// Reconciliation is only valid after the templates directory is installed.
		err := reconcileTemplateOwnership(nonExistentDir, writtenTemplates)
		require.Error(t, err, "reconciliation should reject a non-existent templates directory")
	})
}
