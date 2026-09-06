package installer

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	fileutil "github.com/projectdiscovery/utils/file"
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
	require.FileExists(t, config.DefaultConfig.GetActiveIgnoreFilePath())
	ownership, err := loadTemplateOwnership(templatesTempDir)
	require.NoError(t, err)
	require.NotEmpty(t, ownership.Files, "fresh installation should record official template ownership")
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

func TestWriteTemplateOutput(t *testing.T) {
	t.Run("replaces a final symlink without modifying its target", func(t *testing.T) {
		templatesDir := t.TempDir()
		externalPath := filepath.Join(t.TempDir(), "external.yaml")
		require.NoError(t, os.WriteFile(externalPath, []byte("external"), 0o644))

		outputPath := filepath.Join(templatesDir, "official.yaml")
		if err := os.Symlink(externalPath, outputPath); err != nil {
			t.Skipf("symlinks are unavailable: %v", err)
		}

		_, err := writeTemplateOutput(templatesDir, outputPath, []byte("release"), 0o644)
		require.NoError(t, err)
		require.FileExists(t, outputPath)
		info, err := os.Lstat(outputPath)
		require.NoError(t, err)
		require.Zero(t, info.Mode()&os.ModeSymlink)
		contents, err := os.ReadFile(outputPath)
		require.NoError(t, err)
		require.Equal(t, "release", string(contents))
		require.FileExists(t, externalPath)
		contents, err = os.ReadFile(externalPath)
		require.NoError(t, err)
		require.Equal(t, "external", string(contents))
	})

	t.Run("rejects a parent symlink outside the templates directory", func(t *testing.T) {
		templatesDir := t.TempDir()
		externalDir := t.TempDir()
		linkedParent := filepath.Join(templatesDir, "nested")
		if err := os.Symlink(externalDir, linkedParent); err != nil {
			t.Skipf("symlinks are unavailable: %v", err)
		}

		_, err := writeTemplateOutput(templatesDir, filepath.Join(linkedParent, "official.yaml"), []byte("release"), 0o644)
		require.Error(t, err)
		require.NoFileExists(t, filepath.Join(externalDir, "official.yaml"))
	})

	t.Run("preserves permissions on an existing regular file", func(t *testing.T) {
		templatesDir := t.TempDir()
		outputPath := filepath.Join(templatesDir, "official.yaml")
		require.NoError(t, os.WriteFile(outputPath, []byte("previous"), 0o600))
		previousInfo, err := os.Stat(outputPath)
		require.NoError(t, err)

		_, err = writeTemplateOutput(templatesDir, outputPath, []byte("release"), 0o777)
		require.NoError(t, err)
		info, err := os.Stat(outputPath)
		require.NoError(t, err)
		require.Equal(t, previousInfo.Mode().Perm(), info.Mode().Perm())
	})

	t.Run("reports every directory touched by nested output creation", func(t *testing.T) {
		templatesDir := t.TempDir()
		firstParent := filepath.Join(templatesDir, "first")
		outputParent := filepath.Join(firstParent, "second")
		outputPath := filepath.Join(outputParent, "official.yaml")

		result, err := writeTemplateOutput(templatesDir, outputPath, []byte("release"), 0o644)
		require.NoError(t, err)
		require.ElementsMatch(t, []string{templatesDir, firstParent, outputParent}, result.touchedDirectories)
	})

	t.Run("reports the parent touched by a failed replacement", func(t *testing.T) {
		templatesDir := t.TempDir()
		outputPath := filepath.Join(templatesDir, "existing-directory")
		require.NoError(t, os.Mkdir(outputPath, 0o755))

		result, err := writeTemplateOutput(templatesDir, outputPath, []byte("release"), 0o644)
		require.Error(t, err)
		require.Equal(t, []string{templatesDir}, result.touchedDirectories)
	})
}

func TestSyncTemplateOutputDirectories(t *testing.T) {
	t.Run("syncs each distinct directory once", func(t *testing.T) {
		directories := map[string]struct{}{
			t.TempDir(): {},
			t.TempDir(): {},
		}
		syncCalls := 0

		err := syncTemplateOutputDirectories(directories, func(*os.Root, string) error {
			syncCalls++
			return nil
		})
		require.NoError(t, err)
		require.Equal(t, len(directories), syncCalls)
	})

	t.Run("continues after a sync failure", func(t *testing.T) {
		directories := map[string]struct{}{
			t.TempDir(): {},
			t.TempDir(): {},
		}
		syncErr := errors.New("sync failed")
		syncCalls := 0

		err := syncTemplateOutputDirectories(directories, func(*os.Root, string) error {
			syncCalls++
			if syncCalls == 1 {
				return syncErr
			}
			return nil
		})
		require.ErrorIs(t, err, syncErr)
		require.Equal(t, len(directories), syncCalls)
	})
}

func BenchmarkWriteTemplateOutputs(b *testing.B) {
	b.Run("batched", func(b *testing.B) {
		benchmarkWriteTemplateOutputs(b, false)
	})
	b.Run("per-output-sync", func(b *testing.B) {
		benchmarkWriteTemplateOutputs(b, true)
	})
}

func benchmarkWriteTemplateOutputs(b *testing.B, syncEachOutput bool) {
	rootDir := b.TempDir()
	contents := []byte("id: benchmark\ninfo:\n  name: Benchmark\n  author: test\n  severity: info\n")
	touchedDirectories := make(map[string]struct{})
	b.ReportAllocs()
	b.ResetTimer()

	for index := 0; index < b.N; index++ {
		writePath := filepath.Join(rootDir, fmt.Sprintf("group-%d", index%16), fmt.Sprintf("template-%d.yaml", index))
		outputResult, err := writeTemplateOutput(rootDir, writePath, contents, 0o644)
		if err != nil {
			b.Fatal(err)
		}
		for _, directory := range outputResult.touchedDirectories {
			touchedDirectories[directory] = struct{}{}
		}

		if syncEachOutput {
			output, err := os.OpenFile(writePath, os.O_RDWR, 0)
			if err != nil {
				b.Fatal(err)
			}
			syncErr := output.Sync()
			closeErr := output.Close()
			if err := errors.Join(syncErr, closeErr); err != nil {
				b.Fatal(err)
			}
		}
	}

	if err := syncTemplateOutputDirectories(touchedDirectories, syncTemplateOwnershipDirectory); err != nil {
		b.Fatal(err)
	}
}

func TestGetTemplateOutputLocationRoutesIgnoreFile(t *testing.T) {
	previousConfig := config.DefaultConfig
	templatesDir := t.TempDir()
	cfg := &config.Config{}
	cfg.SetTemplatesDir(templatesDir)
	config.DefaultConfig = cfg
	t.Cleanup(func() { config.DefaultConfig = previousConfig })

	ignoreEntry := filepath.Join(t.TempDir(), config.NucleiIgnoreFileName)
	require.NoError(t, os.WriteFile(ignoreEntry, nil, 0o600))
	info, err := os.Stat(ignoreEntry)
	require.NoError(t, err)
	rootDir, writePath := (&TemplateManager{}).getTemplateOutputLocation(templatesDir, "nuclei-templates/"+config.NucleiIgnoreFileName, info)
	require.Equal(t, templatesDir, rootDir)
	require.Equal(t, cfg.GetActiveIgnoreFilePath(), writePath)
}

func TestWriteTemplateOutputValidatesIgnoreFile(t *testing.T) {
	previousConfig := config.DefaultConfig
	templatesDir := t.TempDir()
	cfg := &config.Config{}
	cfg.SetTemplatesDir(templatesDir)
	config.DefaultConfig = cfg
	t.Cleanup(func() { config.DefaultConfig = previousConfig })

	path := cfg.GetActiveIgnoreFilePath()
	valid := []byte("tags: [weak]\n")
	require.NoError(t, os.WriteFile(path, valid, 0o600))

	_, err := writeTemplateOutput(templatesDir, path, []byte("<html>blocked</html>\n"), 0o644)
	require.Error(t, err)

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, valid, got)

	payload := []byte("files: [blocked.yaml]\n")
	_, err = writeTemplateOutput(templatesDir, path, payload, 0o644)
	require.NoError(t, err)
	got, err = os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, payload, got)
}

func TestCommitTemplateVersionRestoresMemoryOnWriteFailure(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	require.NoError(t, os.WriteFile(stateDir, nil, 0o600))
	cfg := &config.Config{TemplateVersion: "v1.2.3"}
	cfg.SetStateDir(stateDir)

	err := commitTemplateVersion(cfg, "v2.0.0")
	require.Error(t, err)
	require.Equal(t, "v1.2.3", cfg.TemplateVersion)
}

func TestFinalizeTemplateReleaseCommitsVersionLast(t *testing.T) {
	newConfig := func(t *testing.T) *config.Config {
		t.Helper()
		configDir := t.TempDir()
		templatesDir := t.TempDir()
		cfg := &config.Config{Logger: gologger.DefaultLogger}
		cfg.SetConfigDir(configDir)
		cfg.SetTemplatesDir(templatesDir)
		require.NoError(t, os.WriteFile(cfg.GetActiveIgnoreFilePath(), []byte("ignore contents"), 0o600))
		cfg.TemplateVersion = "v1.0.0"

		previousConfig := config.DefaultConfig
		config.DefaultConfig = cfg
		t.Cleanup(func() { config.DefaultConfig = previousConfig })
		return cfg
	}

	t.Run("commits after successful finalization", func(t *testing.T) {
		cfg := newConfig(t)
		templatePath := filepath.Join(cfg.TemplatesDirectory, "official.yaml")
		require.NoError(t, os.WriteFile(templatePath, []byte("id: official\ninfo:\n  name: Official\n  author: test\n  severity: info\n"), 0644))

		tm := &TemplateManager{}
		_, err := tm.finalizeTemplateRelease(cfg, newWrittenTemplates(t, templatePath), "v2.0.0")
		require.NoError(t, err)
		require.Equal(t, "v2.0.0", cfg.TemplateVersion)
	})

	t.Run("preserves version when metadata finalization fails", func(t *testing.T) {
		cfg := newConfig(t)
		templatePath := filepath.Join(cfg.TemplatesDirectory, "official.yaml")
		require.NoError(t, os.WriteFile(templatePath, []byte("id: official\ninfo:\n  name: Official\n  author: test\n  severity: info\n"), 0644))
		require.NoError(t, os.Mkdir(cfg.GetTemplateIndexFilePath(), 0755))
		require.NoError(t, os.WriteFile(filepath.Join(cfg.GetTemplateIndexFilePath(), "keep"), []byte("keep"), 0600))

		tm := &TemplateManager{}
		_, err := tm.finalizeTemplateRelease(cfg, newWrittenTemplates(t, templatePath), "v2.0.0")
		require.Error(t, err)
		require.Equal(t, "v1.0.0", cfg.TemplateVersion)
	})
}

func TestCalculateChecksumMap(t *testing.T) {
	tm := &TemplateManager{}
	previousTemplatesDir := config.DefaultConfig.TemplatesDirectory
	t.Cleanup(func() { config.DefaultConfig.SetTemplatesDir(previousTemplatesDir) })

	t.Run("checksums custom dir sibling prefixes", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "nuclei-checksum-custom-prefix-test-*")
		require.NoError(t, err)
		defer func() {
			_ = os.RemoveAll(tmpDir)
		}()

		config.DefaultConfig.SetTemplatesDir(tmpDir)

		customGitHubDir := filepath.Join(tmpDir, "github")
		require.NoError(t, os.MkdirAll(customGitHubDir, 0755))
		customTemplate := filepath.Join(customGitHubDir, "custom-template.yaml")
		require.NoError(t, os.WriteFile(customTemplate, []byte(`id: custom-template
info:
  name: Custom Template
  author: test
  severity: info`), 0644))

		siblingDir := filepath.Join(tmpDir, "github-evil")
		require.NoError(t, os.MkdirAll(siblingDir, 0755))
		siblingTemplate := filepath.Join(siblingDir, "sibling-template.yaml")
		require.NoError(t, os.WriteFile(siblingTemplate, []byte(`id: sibling-template
info:
  name: Sibling Template
  author: test
  severity: info`), 0644))

		checksums, err := tm.calculateChecksumMap(tmpDir)
		require.NoError(t, err)
		require.NotContains(t, checksums, customTemplate, "custom template should be excluded")
		require.Contains(t, checksums, siblingTemplate, "custom directory sibling prefix should be checksummed")
	})

	t.Run("excludes internal temporary files from checksums", func(t *testing.T) {
		templatesDir := t.TempDir()
		config.DefaultConfig.SetTemplatesDir(templatesDir)

		templateFile := filepath.Join(templatesDir, "template.yaml")
		ownershipTemporary := filepath.Join(templatesDir, templateOwnershipFileName+".tmp-interrupted")
		retiredQuarantine := filepath.Join(templatesDir, templateOwnershipRetiredPrefix+"interrupted")
		nestedDir := filepath.Join(templatesDir, "nested")
		nestedOwnershipTemporary := filepath.Join(nestedDir, templateOwnershipFileName+".tmp-user")
		outputTemporary := filepath.Join(nestedDir, templateOutputTemporaryPrefix+strings.Repeat("a", 32))
		restoreTemporary := filepath.Join(nestedDir, templateOutputTemporaryPrefix+strings.Repeat("b", 32)+"-"+strings.Repeat("c", 32))
		restoreState := filepath.Join(templatesDir, templateOwnershipRestorePrefix+strings.Repeat("d", 64)+"-"+strings.Repeat("e", 32))
		userFileWithSimilarName := filepath.Join(nestedDir, templateOutputTemporaryPrefix+"user.yaml")
		require.NoError(t, os.Mkdir(nestedDir, 0755))
		require.NoError(t, os.WriteFile(templateFile, []byte("template"), 0644))
		require.NoError(t, os.WriteFile(ownershipTemporary, []byte("partial manifest"), 0600))
		require.NoError(t, os.WriteFile(retiredQuarantine, []byte("retired template"), 0600))
		require.NoError(t, os.WriteFile(nestedOwnershipTemporary, []byte("user file"), 0644))
		require.NoError(t, os.WriteFile(outputTemporary, []byte("interrupted write"), 0600))
		require.NoError(t, os.WriteFile(restoreTemporary, []byte("interrupted restore"), 0600))
		require.NoError(t, os.WriteFile(restoreState, nil, 0600))
		require.NoError(t, os.WriteFile(userFileWithSimilarName, []byte("user file"), 0644))

		checksums, err := tm.calculateChecksumMap(templatesDir)
		require.NoError(t, err)
		require.Contains(t, checksums, templateFile)
		require.NotContains(t, checksums, ownershipTemporary)
		require.NotContains(t, checksums, retiredQuarantine)
		require.NotContains(t, checksums, outputTemporary)
		require.NotContains(t, checksums, restoreTemporary)
		require.NotContains(t, checksums, restoreState)
		require.Contains(t, checksums, nestedOwnershipTemporary, "only root-level ownership artifacts are internal metadata")
		require.Contains(t, checksums, userFileWithSimilarName, "only names matching the complete internal write pattern are excluded")
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
		_, err = tm.regenerateTemplateMetadata(config.DefaultConfig)
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

	t.Run("excludes retired templates from the regenerated index", func(t *testing.T) {
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
		retiredTemplate := filepath.Join(tmpDir, "retired-template.yaml")

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
		retiredContent := `id: test-template-retired
info:
  name: Test Template Retired
  author: test
  severity: info`

		require.NoError(t, os.WriteFile(template1, []byte(template1Content), 0644))
		require.NoError(t, os.WriteFile(template2, []byte(template2Content), 0644))
		require.NoError(t, os.WriteFile(retiredTemplate, []byte(retiredContent), 0644))

		// Create initial index with all previously owned templates.
		initialIndex := map[string]string{
			"test-template-1":       template1,
			"test-template-2":       template2,
			"test-template-retired": retiredTemplate,
		}
		err = config.DefaultConfig.WriteTemplatesIndex(initialIndex)
		require.NoError(t, err)

		// Verify initial index contains all templates
		index, err := config.GetNucleiTemplatesIndex()
		require.NoError(t, err)
		require.Contains(t, index, "test-template-retired", "initial index should contain the retired template")

		// Arrange the post-reconciliation tree directly; reconciliation has dedicated coverage.
		require.NoError(t, os.Remove(template2))
		require.NoError(t, os.Remove(retiredTemplate))

		// Regenerate metadata from the arranged post-reconciliation tree.
		_, err = tm.regenerateTemplateMetadata(config.DefaultConfig)
		require.NoError(t, err)

		// The regenerated index excludes templates retired by the release.
		index, err = config.GetNucleiTemplatesIndex()
		require.NoError(t, err)
		require.NotContains(t, index, "test-template-retired", "index should not contain a retired template")
		require.Contains(t, index, "test-template-1", "index should still contain kept template")
		require.NotContains(t, index, "test-template-2", "index should not contain template that was deleted but not cleaned")
	})

	t.Run("excludes retired templates from the regenerated checksum", func(t *testing.T) {
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
		retiredTemplate := filepath.Join(tmpDir, "retired.yaml")

		templateContent := `id: test-template
info:
  name: Test Template
  author: test
  severity: info`

		require.NoError(t, os.WriteFile(keptTemplate, []byte(templateContent), 0644))
		require.NoError(t, os.WriteFile(retiredTemplate, []byte(templateContent), 0644))

		// Create initial checksum with both templates
		checksumMap, err := tm.calculateChecksumMap(tmpDir)
		require.NoError(t, err)
		err = writeChecksumMap(config.DefaultConfig, checksumMap)
		require.NoError(t, err)

		// Verify initial checksum contains both templates
		initialChecksums, err := tm.getChecksumFromDir(tmpDir)
		require.NoError(t, err)
		require.Contains(t, initialChecksums, retiredTemplate, "initial checksum should contain the retired template")

		// Arrange the post-reconciliation tree directly; reconciliation has dedicated coverage.
		require.NoError(t, os.Remove(retiredTemplate))

		// Regenerate metadata from the arranged post-reconciliation tree.
		_, err = tm.regenerateTemplateMetadata(config.DefaultConfig)
		require.NoError(t, err)

		// The regenerated checksum excludes templates retired by the release.
		checksums, err := tm.getChecksumFromDir(tmpDir)
		require.NoError(t, err)
		require.NotContains(t, checksums, retiredTemplate, "checksum should not contain a retired template")
		require.Contains(t, checksums, keptTemplate, "checksum should still contain kept template")
	})

	t.Run("reconciles ownership before metadata regeneration", func(t *testing.T) {
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
		retired1 := filepath.Join(tmpDir, "cves", "2022", "old-cve.yaml")
		retired2 := filepath.Join(tmpDir, "exposures", "old-exposure.yaml")

		require.NoError(t, os.MkdirAll(filepath.Dir(template1), 0755))
		require.NoError(t, os.MkdirAll(filepath.Dir(retired1), 0755))
		require.NoError(t, os.MkdirAll(filepath.Dir(retired2), 0755))

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
		retired1Content := `id: old-cve
info:
  name: Old CVE
  author: test
  severity: info`
		retired2Content := `id: old-exposure
info:
  name: Old Exposure
  author: test
  severity: info`

		require.NoError(t, os.WriteFile(template1, []byte(template1Content), 0644))
		require.NoError(t, os.WriteFile(template2, []byte(template2Content), 0644))
		require.NoError(t, os.WriteFile(retired1, []byte(retired1Content), 0644))
		require.NoError(t, os.WriteFile(retired2, []byte(retired2Content), 0644))
		seedTemplateOwnership(t, tmpDir, template1, template2, retired1, retired2)

		// The current release retains template1 and template2.
		absTemplate1, _ := filepath.Abs(template1)
		absTemplate2, _ := filepath.Abs(template2)
		// Normalize paths consistently with ownership reconciliation.
		absTemplate1 = filepath.Clean(absTemplate1)
		absTemplate2 = filepath.Clean(absTemplate2)
		writtenTemplates := newWrittenTemplates(t, absTemplate1, absTemplate2)

		// Reconcile prior ownership with the current release.
		err = reconcileTemplateOwnership(tmpDir, writtenTemplates)
		require.NoError(t, err)
		require.NoFileExists(t, retired1, "retired template 1 should be deleted")
		require.NoFileExists(t, retired2, "retired template 2 should be deleted")

		// Regenerate metadata (simulating what updateTemplatesAt does)
		_, err = tm.regenerateTemplateMetadata(config.DefaultConfig)
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
		require.NotContains(t, checksums, retired1, "checksum should not contain deleted template")
		require.NotContains(t, checksums, retired2, "checksum should not contain deleted template")

		// Verify empty directories are purged
		require.False(t, fileutil.FolderExists(filepath.Dir(retired1)), "empty directory should be purged")
		require.False(t, fileutil.FolderExists(filepath.Dir(retired2)), "empty directory should be purged")
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
		_, err = tm.regenerateTemplateMetadata(config.DefaultConfig)
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
		_, err = tm.regenerateTemplateMetadata(config.DefaultConfig)
		require.NoError(t, err)

		// Verify empty directories were purged
		require.False(t, fileutil.FolderExists(emptyDir1), "empty nested directory should be purged")
		require.False(t, fileutil.FolderExists(emptyDir2), "empty directory should be purged")
		require.True(t, fileutil.FolderExists(filepath.Dir(templateFile)), "directory with template should not be purged")
	})
}
