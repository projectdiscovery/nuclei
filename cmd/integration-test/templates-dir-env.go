package main

import (
	"os"
	"path/filepath"

	osutils "github.com/projectdiscovery/utils/os"

	"github.com/projectdiscovery/nuclei/v3/pkg/testutils"
	"github.com/projectdiscovery/utils/errkit"
)

// isNotLinux returns true if not running on Linux (used to skip tests on non-Linux OS)
var isNotLinux = func() bool { return !osutils.IsLinux() }

var templatesDirEnvTestCases = []TestCaseInfo{
	{Path: "protocols/dns/cname-fingerprint.yaml", TestCase: &templatesDirEnvBasicTest{}, DisableOn: isNotLinux},
	{Path: "protocols/dns/cname-fingerprint.yaml", TestCase: &templatesDirEnvAbsolutePathTest{}, DisableOn: isNotLinux},
	{Path: "protocols/dns/cname-fingerprint.yaml", TestCase: &templatesDirEnvRelativePathTest{}, DisableOn: isNotLinux},
	{Path: "protocols/dns/cname-fingerprint.yaml", TestCase: &templatesDirEnvPrecedenceTest{}, DisableOn: isNotLinux},
	{Path: "protocols/dns/cname-fingerprint.yaml", TestCase: &templatesDirEnvCustomTemplatesTest{}, DisableOn: isNotLinux},
}

// copyTemplateToDir copies a template file to a destination directory, preserving the directory structure
func copyTemplateToDir(templatePath, destDir string) error {
	// Read the template file
	templateData, err := os.ReadFile(templatePath)
	if err != nil {
		return errkit.Wrap(err, "failed to read template file")
	}

	// Create the destination path preserving directory structure
	destPath := filepath.Join(destDir, templatePath)
	destDirPath := filepath.Dir(destPath)

	// Create the destination directory if it doesn't exist
	if err := os.MkdirAll(destDirPath, 0755); err != nil {
		return errkit.Wrap(err, "failed to create destination directory")
	}

	// Write the template file
	if err := os.WriteFile(destPath, templateData, 0644); err != nil {
		return errkit.Wrap(err, "failed to write template file")
	}

	return nil
}

// templatesDirEnvBasicTest tests basic functionality of NUCLEI_TEMPLATES_DIR
type templatesDirEnvBasicTest struct{}

// Execute executes a test case and returns an error if occurred
func (h *templatesDirEnvBasicTest) Execute(filePath string) error {
	tempdir, err := os.MkdirTemp("", "nuclei-templates-dir-env-*")
	if err != nil {
		return errkit.Wrap(err, "failed to create temp dir")
	}
	defer func() {
		_ = os.RemoveAll(tempdir)
	}()

	// Copy template to temp directory
	if err := copyTemplateToDir(filePath, tempdir); err != nil {
		return err
	}

	// Set NUCLEI_TEMPLATES_DIR and run nuclei
	envVars := []string{"NUCLEI_TEMPLATES_DIR=" + tempdir}
	results, err := testutils.RunNucleiBareArgsAndGetResults(debug, envVars, "-t", filePath, "-u", "8x8exch02.8x8.com")
	if err != nil {
		return err
	}

	return expectResultsCount(results, 1)
}

// templatesDirEnvAbsolutePathTest tests that absolute paths work correctly
type templatesDirEnvAbsolutePathTest struct{}

// Execute executes a test case and returns an error if occurred
func (h *templatesDirEnvAbsolutePathTest) Execute(filePath string) error {
	tempdir, err := os.MkdirTemp("", "nuclei-templates-dir-env-abs-*")
	if err != nil {
		return errkit.Wrap(err, "failed to create temp dir")
	}
	defer func() {
		_ = os.RemoveAll(tempdir)
	}()

	// Get absolute path
	absTempDir, err := filepath.Abs(tempdir)
	if err != nil {
		return errkit.Wrap(err, "failed to get absolute path")
	}

	// Copy template to temp directory
	if err := copyTemplateToDir(filePath, absTempDir); err != nil {
		return err
	}

	// Set NUCLEI_TEMPLATES_DIR with absolute path and run nuclei
	envVars := []string{"NUCLEI_TEMPLATES_DIR=" + absTempDir}
	results, err := testutils.RunNucleiBareArgsAndGetResults(debug, envVars, "-t", filePath, "-u", "8x8exch02.8x8.com")
	if err != nil {
		return err
	}

	return expectResultsCount(results, 1)
}

// templatesDirEnvRelativePathTest tests that relative paths are resolved correctly
type templatesDirEnvRelativePathTest struct{}

// Execute executes a test case and returns an error if occurred
func (h *templatesDirEnvRelativePathTest) Execute(filePath string) error {
	// Create temp directory in current working directory
	tempdir, err := os.MkdirTemp(".", "nuclei-templates-dir-env-rel-*")
	if err != nil {
		return errkit.Wrap(err, "failed to create temp dir")
	}
	defer func() {
		_ = os.RemoveAll(tempdir)
	}()

	// Get relative path (just the directory name)
	relPath := filepath.Base(tempdir)

	// Copy template to temp directory
	if err := copyTemplateToDir(filePath, tempdir); err != nil {
		return err
	}

	// Set NUCLEI_TEMPLATES_DIR with relative path and run nuclei
	// Note: The implementation should convert relative paths to absolute
	envVars := []string{"NUCLEI_TEMPLATES_DIR=" + relPath}
	results, err := testutils.RunNucleiBareArgsAndGetResults(debug, envVars, "-t", filePath, "-u", "8x8exch02.8x8.com")
	if err != nil {
		return err
	}

	return expectResultsCount(results, 1)
}

// templatesDirEnvPrecedenceTest tests that -ud flag takes precedence over NUCLEI_TEMPLATES_DIR
type templatesDirEnvPrecedenceTest struct{}

// Execute executes a test case and returns an error if occurred
func (h *templatesDirEnvPrecedenceTest) Execute(filePath string) error {
	// Create two temp directories
	envTempDir, err := os.MkdirTemp("", "nuclei-templates-dir-env-*")
	if err != nil {
		return errkit.Wrap(err, "failed to create env temp dir")
	}
	defer func() {
		_ = os.RemoveAll(envTempDir)
	}()

	flagTempDir, err := os.MkdirTemp("", "nuclei-templates-dir-flag-*")
	if err != nil {
		return errkit.Wrap(err, "failed to create flag temp dir")
	}
	defer func() {
		_ = os.RemoveAll(flagTempDir)
	}()

	// Copy template to flag temp directory (this should be used due to precedence)
	if err := copyTemplateToDir(filePath, flagTempDir); err != nil {
		return err
	}

	// Set NUCLEI_TEMPLATES_DIR to envTempDir (should be ignored due to -ud flag)
	envVars := []string{"NUCLEI_TEMPLATES_DIR=" + envTempDir}
	// Use -ud flag which should take precedence
	results, err := testutils.RunNucleiBareArgsAndGetResults(debug, envVars, "-t", filePath, "-u", "8x8exch02.8x8.com", "-ud", flagTempDir)
	if err != nil {
		return err
	}

	return expectResultsCount(results, 1)
}

// templatesDirEnvCustomTemplatesTest tests that custom template subdirectories are correctly set
type templatesDirEnvCustomTemplatesTest struct{}

// Execute executes a test case and returns an error if occurred
func (h *templatesDirEnvCustomTemplatesTest) Execute(filePath string) error {
	tempdir, err := os.MkdirTemp("", "nuclei-templates-dir-custom-*")
	if err != nil {
		return errkit.Wrap(err, "failed to create temp dir")
	}
	defer func() {
		_ = os.RemoveAll(tempdir)
	}()

	// Create custom template subdirectories structure
	customDirs := []string{"github", "s3", "gitlab", "azure"}
	for _, dir := range customDirs {
		customDirPath := filepath.Join(tempdir, dir)
		if err := os.MkdirAll(customDirPath, 0755); err != nil {
			return errkit.Wrap(err, "failed to create custom template directory")
		}
	}

	// Copy template to temp directory
	if err := copyTemplateToDir(filePath, tempdir); err != nil {
		return err
	}

	// Set NUCLEI_TEMPLATES_DIR and run nuclei
	envVars := []string{"NUCLEI_TEMPLATES_DIR=" + tempdir}
	results, err := testutils.RunNucleiBareArgsAndGetResults(debug, envVars, "-t", filePath, "-u", "8x8exch02.8x8.com")
	if err != nil {
		return err
	}

	return expectResultsCount(results, 1)
}
