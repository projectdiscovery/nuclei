package installer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	fileutil "github.com/projectdiscovery/utils/file"
	mapsutil "github.com/projectdiscovery/utils/maps"
	"github.com/stretchr/testify/require"
)

func TestTemplateInstallation(t *testing.T) {
	// test that the templates are installed correctly
	// along with necessary changes that are made
	HideProgressBar = true

	tm := &TemplateManager{}
	dir, err := os.MkdirTemp("", "nuclei-templates-*")
	require.Nil(t, err)
	cfgdir, err := os.MkdirTemp("", "nuclei-config-*")
	require.Nil(t, err)
	defer func() {
		_ = os.RemoveAll(dir)
		_ = os.RemoveAll(cfgdir)
	}()

	// set the config directory to a temporary directory
	config.DefaultConfig.SetConfigDir(cfgdir)
	// set the templates directory to a temporary directory
	templatesTempDir := filepath.Join(dir, "templates")
	config.DefaultConfig.SetTemplatesDir(templatesTempDir)

	err = tm.FreshInstallIfNotExists()
	if err != nil {
		if strings.Contains(err.Error(), "rate limit") {
			t.Skip("Skipping test due to github rate limit")
		}
		require.Nil(t, err)
	}

	// we should switch to more fine granular tests for template
	// integrity, but for now, we just check that the templates are installed
	counter := 0
	err = filepath.Walk(templatesTempDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			counter++
		}
		return nil
	})
	require.Nil(t, err)

	// we should have at least 1000 templates
	require.Greater(t, counter, 1000)
	// every time we install templates, it should override the ignore file with latest one
	require.FileExists(t, config.DefaultConfig.GetIgnoreFilePath())
	t.Logf("Installed %d templates", counter)
}

func TestIsOutdatedVersion(t *testing.T) {
	testCases := []struct {
		current  string
		latest   string
		expected bool
		desc     string
	}{
		// Test the empty latest version case (main bug fix)
		{"v10.2.7", "", false, "Empty latest version should not trigger update"},

		// Test same versions
		{"v10.2.7", "v10.2.7", false, "Same versions should not trigger update"},

		// Test outdated version
		{"v10.2.6", "v10.2.7", true, "Older version should trigger update"},

		// Test newer current version (edge case)
		{"v10.2.8", "v10.2.7", false, "Newer current version should not trigger update"},

		// Test dev versions
		{"v10.2.7-dev", "v10.2.7", false, "Dev version matching release should not trigger update"},
		{"v10.2.6-dev", "v10.2.7", true, "Outdated dev version should trigger update"},

		// Test invalid semver fallback
		{"invalid-version", "v10.2.7", true, "Invalid current version should trigger update (fallback)"},
		{"v10.2.7", "invalid-version", true, "Invalid latest version should trigger update (fallback)"},
		{"same-invalid", "same-invalid", false, "Same invalid versions should not trigger update (fallback)"},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			result := config.IsOutdatedVersion(tc.current, tc.latest)
			require.Equal(t, tc.expected, result,
				"IsOutdatedVersion(%q, %q) = %t, expected %t",
				tc.current, tc.latest, result, tc.expected)
		})
	}
}

func TestCleanupOrphanedTemplates(t *testing.T) {
	HideProgressBar = true

	tm := &TemplateManager{}

	t.Run("removes orphaned templates", func(t *testing.T) {
		// Create temporary directories
		tmpDir, err := os.MkdirTemp("", "nuclei-cleanup-test-*")
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

		// Create subdirectories for templates
		templatesDir1 := filepath.Join(tmpDir, "cves", "2023")
		templatesDir2 := filepath.Join(tmpDir, "exposures", "configs")
		require.NoError(t, os.MkdirAll(templatesDir1, 0755))
		require.NoError(t, os.MkdirAll(templatesDir2, 0755))

		// Create template files
		template1 := filepath.Join(templatesDir1, "CVE-2023-1234.yaml")
		template2 := filepath.Join(templatesDir1, "CVE-2023-5678.yaml")
		template3 := filepath.Join(templatesDir2, "git-config-exposure.yaml")
		orphanedTemplate1 := filepath.Join(templatesDir1, "old-template.yaml")
		orphanedTemplate2 := filepath.Join(templatesDir2, "removed-template.yaml")

		// Write valid template files
		templateContent := `id: test-template
info:
  name: Test Template
  author: test
  severity: info`
		require.NoError(t, os.WriteFile(template1, []byte(templateContent), 0644))
		require.NoError(t, os.WriteFile(template2, []byte(templateContent), 0644))
		require.NoError(t, os.WriteFile(template3, []byte(templateContent), 0644))
		require.NoError(t, os.WriteFile(orphanedTemplate1, []byte(templateContent), 0644))
		require.NoError(t, os.WriteFile(orphanedTemplate2, []byte(templateContent), 0644))

		// Simulate written paths from new release (only template1, template2, template3)
		writtenPaths := mapsutil.NewSyncLockMap[string, struct{}]()
		absTemplate1, _ := filepath.Abs(template1)
		absTemplate2, _ := filepath.Abs(template2)
		absTemplate3, _ := filepath.Abs(template3)
		_ = writtenPaths.Set(absTemplate1, struct{}{})
		_ = writtenPaths.Set(absTemplate2, struct{}{})
		_ = writtenPaths.Set(absTemplate3, struct{}{})

		// Run cleanup
		err = tm.cleanupOrphanedTemplates(tmpDir, writtenPaths)
		require.NoError(t, err)

		// Verify orphaned templates were removed
		require.NoFileExists(t, orphanedTemplate1, "orphaned template should be removed")
		require.NoFileExists(t, orphanedTemplate2, "orphaned template should be removed")

		// Verify non-orphaned templates still exist
		require.FileExists(t, template1, "template from new release should exist")
		require.FileExists(t, template2, "template from new release should exist")
		require.FileExists(t, template3, "template from new release should exist")
	})

	t.Run("preserves custom templates", func(t *testing.T) {
		// Create temporary directories
		tmpDir, err := os.MkdirTemp("", "nuclei-cleanup-custom-test-*")
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

		// Empty written paths (simulating no custom templates in new release)
		writtenPaths := mapsutil.NewSyncLockMap[string, struct{}]()

		// Run cleanup
		err = tm.cleanupOrphanedTemplates(tmpDir, writtenPaths)
		require.NoError(t, err)

		// Verify custom template was NOT removed
		require.FileExists(t, customTemplate, "custom template should be preserved")
	})

	t.Run("skips non-template files", func(t *testing.T) {
		// Create temporary directories
		tmpDir, err := os.MkdirTemp("", "nuclei-cleanup-nontemplate-test-*")
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

		// Create non-template files
		readmeFile := filepath.Join(tmpDir, "README.md")
		configFile := filepath.Join(tmpDir, "cves.json")
		checksumFile := filepath.Join(tmpDir, ".checksum")

		require.NoError(t, os.WriteFile(readmeFile, []byte("# Templates"), 0644))
		require.NoError(t, os.WriteFile(configFile, []byte("{}"), 0644))
		require.NoError(t, os.WriteFile(checksumFile, []byte(""), 0644))

		// Empty written paths
		writtenPaths := mapsutil.NewSyncLockMap[string, struct{}]()

		// Run cleanup
		err = tm.cleanupOrphanedTemplates(tmpDir, writtenPaths)
		require.NoError(t, err)

		// Verify non-template files were NOT removed
		require.FileExists(t, readmeFile, "README.md should be preserved")
		require.FileExists(t, configFile, "config file should be preserved")
		require.FileExists(t, checksumFile, "checksum file should be preserved")
	})

	t.Run("handles empty written paths", func(t *testing.T) {
		// Create temporary directories
		tmpDir, err := os.MkdirTemp("", "nuclei-cleanup-empty-test-*")
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

		// Create template files
		template1 := filepath.Join(tmpDir, "template1.yaml")
		templateContent := `id: test-template
info:
  name: Test Template
  author: test
  severity: info`
		require.NoError(t, os.WriteFile(template1, []byte(templateContent), 0644))

		// Empty written paths
		writtenPaths := mapsutil.NewSyncLockMap[string, struct{}]()

		// Run cleanup
		err = tm.cleanupOrphanedTemplates(tmpDir, writtenPaths)
		require.NoError(t, err)

		// Verify template was removed (since it's not in written paths)
		require.NoFileExists(t, template1, "template should be removed when not in written paths")
	})

	t.Run("handles relative and absolute paths correctly", func(t *testing.T) {
		// Create temporary directories
		tmpDir, err := os.MkdirTemp("", "nuclei-cleanup-path-test-*")
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

		// Create template file
		template1 := filepath.Join(tmpDir, "template1.yaml")
		templateContent := `id: test-template
info:
  name: Test Template
  author: test
  severity: info`
		require.NoError(t, os.WriteFile(template1, []byte(templateContent), 0644))

		// Use relative path in written paths
		writtenPaths := mapsutil.NewSyncLockMap[string, struct{}]()
		_ = writtenPaths.Set(template1, struct{}{}) // relative path

		// Run cleanup - should normalize paths correctly
		err = tm.cleanupOrphanedTemplates(tmpDir, writtenPaths)
		require.NoError(t, err)

		// Verify template was NOT removed (it was in written paths)
		require.FileExists(t, template1, "template should be preserved when in written paths")
	})

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

		// Written paths from new release
		writtenPaths := mapsutil.NewSyncLockMap[string, struct{}]()

		// Run cleanup - should handle empty directory gracefully
		err = tm.cleanupOrphanedTemplates(tmpDir, writtenPaths)
		require.NoError(t, err, "cleanup should handle empty directory without error")

		// Directory should still exist after cleanup
		require.True(t, fileutil.FolderExists(tmpDir), "templates directory should still exist")
	})

	t.Run("handles non-existent directory gracefully", func(t *testing.T) {
		// Use a non-existent directory path
		nonExistentDir := "/tmp/nuclei-test-non-existent-dir-12345"

		// Ensure it doesn't exist
		_ = os.RemoveAll(nonExistentDir)
		require.False(t, fileutil.FolderExists(nonExistentDir), "directory should not exist")

		writtenPaths := mapsutil.NewSyncLockMap[string, struct{}]()

		// Run cleanup - should handle non-existent directory gracefully
		err := tm.cleanupOrphanedTemplates(nonExistentDir, writtenPaths)
		require.NoError(t, err, "cleanup should handle non-existent directory without error")
	})
}

func TestRegenerateTemplateMetadata(t *testing.T) {
	HideProgressBar = true
	tm := &TemplateManager{}

	t.Run("creates index and checksum files", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "nuclei-metadata-test-*")
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

		// Create template files with unique IDs
		template1 := filepath.Join(tmpDir, "template1.yaml")
		template2 := filepath.Join(tmpDir, "cves", "template2.yaml")
		require.NoError(t, os.MkdirAll(filepath.Dir(template2), 0755))

		template1Content := `id: template-one
info:
  name: Template One
  author: test
  severity: info`
		template2Content := `id: template-two
info:
  name: Template Two
  author: test
  severity: high`

		require.NoError(t, os.WriteFile(template1, []byte(template1Content), 0644))
		require.NoError(t, os.WriteFile(template2, []byte(template2Content), 0644))

		// Regenerate metadata
		err = tm.regenerateTemplateMetadata(tmpDir)
		require.NoError(t, err)

		// Verify index file was created
		indexPath := config.DefaultConfig.GetTemplateIndexFilePath()
		require.FileExists(t, indexPath, "template index file should be created")

		// Verify checksum file was created
		checksumPath := config.DefaultConfig.GetChecksumFilePath()
		require.FileExists(t, checksumPath, "checksum file should be created")

		// Verify index contains both templates
		index, err := config.GetNucleiTemplatesIndex()
		require.NoError(t, err)
		require.Contains(t, index, "template-one", "index should contain template-one")
		require.Contains(t, index, "template-two", "index should contain template-two")

		// Verify checksum file contains both templates
		checksums, err := tm.getChecksumFromDir(tmpDir)
		require.NoError(t, err)
		require.Contains(t, checksums, template1, "checksum should contain template1")
		require.Contains(t, checksums, template2, "checksum should contain template2")
	})

	t.Run("excludes deleted templates from index after cleanup", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "nuclei-metadata-cleanup-test-*")
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

		// Create template files
		template1 := filepath.Join(tmpDir, "kept-template.yaml")
		template2 := filepath.Join(tmpDir, "deleted-template.yaml")
		orphanedTemplate := filepath.Join(tmpDir, "orphaned-template.yaml")

		template1Content := `id: test-template-1
info:
  name: Test Template 1
  author: test
  severity: info`
		template2Content := `id: test-template-2
info:
  name: Test Template 2
  author: test
  severity: info`
		orphanedContent := `id: test-template-orphaned
info:
  name: Test Template Orphaned
  author: test
  severity: info`

		require.NoError(t, os.WriteFile(template1, []byte(template1Content), 0644))
		require.NoError(t, os.WriteFile(template2, []byte(template2Content), 0644))
		require.NoError(t, os.WriteFile(orphanedTemplate, []byte(orphanedContent), 0644))

		// Create initial index with all templates (simulating state before cleanup)
		initialIndex := map[string]string{
			"test-template-1":        template1,
			"test-template-2":        template2,
			"test-template-orphaned": orphanedTemplate,
		}
		err = config.DefaultConfig.WriteTemplatesIndex(initialIndex)
		require.NoError(t, err)

		// Verify initial index contains all templates
		index, err := config.GetNucleiTemplatesIndex()
		require.NoError(t, err)
		require.Contains(t, index, "test-template-orphaned", "initial index should contain orphaned template")

		// Simulate cleanup: remove orphaned template
		writtenPaths := mapsutil.NewSyncLockMap[string, struct{}]()
		absTemplate1, _ := filepath.Abs(template1)
		_ = writtenPaths.Set(absTemplate1, struct{}{})

		err = tm.cleanupOrphanedTemplates(tmpDir, writtenPaths)
		require.NoError(t, err)
		require.NoFileExists(t, orphanedTemplate, "orphaned template should be deleted")

		// Regenerate metadata after cleanup
		err = tm.regenerateTemplateMetadata(tmpDir)
		require.NoError(t, err)

		// Verify index no longer contains deleted template
		index, err = config.GetNucleiTemplatesIndex()
		require.NoError(t, err)
		require.NotContains(t, index, "test-template-orphaned", "index should not contain deleted orphaned template")
		require.Contains(t, index, "test-template-1", "index should still contain kept template")
		require.NotContains(t, index, "test-template-2", "index should not contain template that was deleted but not cleaned")
	})

	t.Run("excludes deleted templates from checksum after cleanup", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "nuclei-checksum-cleanup-test-*")
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

		// Create template files
		keptTemplate := filepath.Join(tmpDir, "kept.yaml")
		orphanedTemplate := filepath.Join(tmpDir, "orphaned.yaml")

		templateContent := `id: test-template
info:
  name: Test Template
  author: test
  severity: info`

		require.NoError(t, os.WriteFile(keptTemplate, []byte(templateContent), 0644))
		require.NoError(t, os.WriteFile(orphanedTemplate, []byte(templateContent), 0644))

		// Create initial checksum with both templates
		err = tm.writeChecksumFileInDir(tmpDir)
		require.NoError(t, err)

		// Verify initial checksum contains both templates
		initialChecksums, err := tm.getChecksumFromDir(tmpDir)
		require.NoError(t, err)
		require.Contains(t, initialChecksums, orphanedTemplate, "initial checksum should contain orphaned template")

		// Simulate cleanup: remove orphaned template
		writtenPaths := mapsutil.NewSyncLockMap[string, struct{}]()
		absKept, _ := filepath.Abs(keptTemplate)
		_ = writtenPaths.Set(absKept, struct{}{})

		err = tm.cleanupOrphanedTemplates(tmpDir, writtenPaths)
		require.NoError(t, err)
		require.NoFileExists(t, orphanedTemplate, "orphaned template should be deleted")

		// Regenerate metadata after cleanup
		err = tm.regenerateTemplateMetadata(tmpDir)
		require.NoError(t, err)

		// Verify checksum no longer contains deleted template
		checksums, err := tm.getChecksumFromDir(tmpDir)
		require.NoError(t, err)
		require.NotContains(t, checksums, orphanedTemplate, "checksum should not contain deleted orphaned template")
		require.Contains(t, checksums, keptTemplate, "checksum should still contain kept template")
	})

	t.Run("cleanup and metadata regeneration integration", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "nuclei-integration-test-*")
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

		// Create multiple templates
		template1 := filepath.Join(tmpDir, "cves", "2023", "cve1.yaml")
		template2 := filepath.Join(tmpDir, "cves", "2023", "cve2.yaml")
		orphaned1 := filepath.Join(tmpDir, "cves", "2022", "old-cve.yaml")
		orphaned2 := filepath.Join(tmpDir, "exposures", "old-exposure.yaml")

		require.NoError(t, os.MkdirAll(filepath.Dir(template1), 0755))
		require.NoError(t, os.MkdirAll(filepath.Dir(orphaned1), 0755))
		require.NoError(t, os.MkdirAll(filepath.Dir(orphaned2), 0755))

		template1Content := `id: cve1
info:
  name: CVE1
  author: test
  severity: info`
		template2Content := `id: cve2
info:
  name: CVE2
  author: test
  severity: info`
		orphaned1Content := `id: old-cve
info:
  name: Old CVE
  author: test
  severity: info`
		orphaned2Content := `id: old-exposure
info:
  name: Old Exposure
  author: test
  severity: info`

		require.NoError(t, os.WriteFile(template1, []byte(template1Content), 0644))
		require.NoError(t, os.WriteFile(template2, []byte(template2Content), 0644))
		require.NoError(t, os.WriteFile(orphaned1, []byte(orphaned1Content), 0644))
		require.NoError(t, os.WriteFile(orphaned2, []byte(orphaned2Content), 0644))

		// Simulate written paths from new release
		writtenPaths := mapsutil.NewSyncLockMap[string, struct{}]()
		absTemplate1, _ := filepath.Abs(template1)
		absTemplate2, _ := filepath.Abs(template2)
		_ = writtenPaths.Set(absTemplate1, struct{}{})
		_ = writtenPaths.Set(absTemplate2, struct{}{})

		// Perform cleanup
		err = tm.cleanupOrphanedTemplates(tmpDir, writtenPaths)
		require.NoError(t, err)
		require.NoFileExists(t, orphaned1, "orphaned template 1 should be deleted")
		require.NoFileExists(t, orphaned2, "orphaned template 2 should be deleted")

		// Regenerate metadata (simulating what updateTemplatesAt does)
		err = tm.regenerateTemplateMetadata(tmpDir)
		require.NoError(t, err)

		// Verify index only contains kept templates
		index, err := config.GetNucleiTemplatesIndex()
		require.NoError(t, err)
		require.Contains(t, index, "cve1", "index should contain kept template cve1")
		require.Contains(t, index, "cve2", "index should contain kept template cve2")
		require.NotContains(t, index, "old-cve", "index should not contain deleted template")
		require.NotContains(t, index, "old-exposure", "index should not contain deleted template")

		// Verify checksum only contains kept templates
		checksums, err := tm.getChecksumFromDir(tmpDir)
		require.NoError(t, err)
		require.Contains(t, checksums, template1, "checksum should contain kept template1")
		require.Contains(t, checksums, template2, "checksum should contain kept template2")
		require.NotContains(t, checksums, orphaned1, "checksum should not contain deleted template")
		require.NotContains(t, checksums, orphaned2, "checksum should not contain deleted template")

		// Verify empty directories are purged
		require.False(t, fileutil.FolderExists(filepath.Dir(orphaned1)), "empty directory should be purged")
		require.False(t, fileutil.FolderExists(filepath.Dir(orphaned2)), "empty directory should be purged")
	})

	t.Run("handles empty templates directory", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "nuclei-metadata-empty-test-*")
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

		// Ensure templates directory exists (even if empty)
		require.NoError(t, os.MkdirAll(tmpDir, 0755))

		// Regenerate metadata on empty directory
		err = tm.regenerateTemplateMetadata(tmpDir)
		require.NoError(t, err, "should handle empty directory without error")

		// Index should exist but be empty or minimal
		indexPath := config.DefaultConfig.GetTemplateIndexFilePath()
		if fileutil.FileExists(indexPath) {
			index, err := config.GetNucleiTemplatesIndex()
			require.NoError(t, err)
			require.Empty(t, index, "index should be empty for empty templates directory")
		}
	})

	t.Run("purges empty directories", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "nuclei-metadata-purge-test-*")
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

		// Create empty nested directories
		emptyDir1 := filepath.Join(tmpDir, "empty1", "nested", "deep")
		emptyDir2 := filepath.Join(tmpDir, "empty2")
		require.NoError(t, os.MkdirAll(emptyDir1, 0755))
		require.NoError(t, os.MkdirAll(emptyDir2, 0755))

		// Create one template in a different directory
		templateFile := filepath.Join(tmpDir, "kept", "template.yaml")
		require.NoError(t, os.MkdirAll(filepath.Dir(templateFile), 0755))
		require.NoError(t, os.WriteFile(templateFile, []byte(`id: kept-template
info:
  name: Kept
  author: test
  severity: info`), 0644))

		// Regenerate metadata (should purge empty directories)
		err = tm.regenerateTemplateMetadata(tmpDir)
		require.NoError(t, err)

		// Verify empty directories were purged
		require.False(t, fileutil.FolderExists(emptyDir1), "empty nested directory should be purged")
		require.False(t, fileutil.FolderExists(emptyDir2), "empty directory should be purged")
		require.True(t, fileutil.FolderExists(filepath.Dir(templateFile)), "directory with template should not be purged")
	})
}
