package main

import (
	"os"
	"testing"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestProcessProfileExtras_MetadataFields(t *testing.T) {
	// Save and restore global options
	origOptions := options
	origTempFiles := tempFiles
	defer func() {
		// Clean up any temp files created during the test
		for _, f := range tempFiles {
			_ = os.Remove(f)
		}
		options = origOptions
		tempFiles = origTempFiles
	}()

	options = &types.Options{Logger: gologger.DefaultLogger}
	tempFiles = nil

	err := processProfileExtras("testdata/test-profile-with-extras.yaml")
	require.NoError(t, err, "processProfileExtras should not return an error for a valid profile")

	require.Equal(t, "test-profile", options.ProfileID, "ProfileID should be extracted")
	require.Equal(t, "Test Profile", options.ProfileName, "ProfileName should be extracted")
	require.Equal(t, "Testing profile improvements", options.ProfilePurpose, "ProfilePurpose should be extracted")
	require.Equal(t, "This profile demonstrates metadata fields and inline secrets", options.ProfileDescription, "ProfileDescription should be extracted")
}

func TestProcessProfileExtras_InlineSecrets(t *testing.T) {
	origOptions := options
	origTempFiles := tempFiles
	defer func() {
		options = origOptions
		tempFiles = origTempFiles
	}()

	options = &types.Options{Logger: gologger.DefaultLogger}
	tempFiles = nil

	err := processProfileExtras("testdata/test-profile-with-extras.yaml")
	require.NoError(t, err, "processProfileExtras should not return an error for valid inline secrets")

	// InlineSecretsYAML should be populated
	require.NotEmpty(t, options.InlineSecretsYAML, "InlineSecretsYAML should be populated")

	// A temp file should have been created and added to SecretsFile
	require.Len(t, options.SecretsFile, 1, "SecretsFile should have one entry for inline secrets")

	// Verify the temp file exists and contains valid YAML
	tmpPath := string(options.SecretsFile[0])
	_, err = os.Stat(tmpPath)
	require.NoError(t, err, "temp secrets file should exist")

	// The temp file should also be tracked for cleanup
	require.Len(t, tempFiles, 1, "tempFiles should track the created file")
	require.Equal(t, tmpPath, tempFiles[0])

	// Clean up
	_ = os.Remove(tmpPath)
}

func TestProcessProfileExtras_NoSecretsField(t *testing.T) {
	origOptions := options
	defer func() { options = origOptions }()

	// Create a temp profile without secrets
	tmpFile, err := os.CreateTemp("", "test-profile-*.yaml")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString(`
id: simple-profile
name: Simple Profile
tags:
  - cve
timeout: 30
`)
	require.NoError(t, err)
	_ = tmpFile.Close()

	options = &types.Options{Logger: gologger.DefaultLogger}

	err = processProfileExtras(tmpFile.Name())
	require.NoError(t, err, "processProfileExtras should not return an error for a profile without secrets")

	require.Equal(t, "simple-profile", options.ProfileID)
	require.Equal(t, "Simple Profile", options.ProfileName)
	require.Empty(t, options.SecretsFile, "SecretsFile should be empty when no secrets in profile")
	require.Empty(t, options.InlineSecretsYAML, "InlineSecretsYAML should be empty when no secrets in profile")
}

func TestProcessProfileExtras_InvalidFile(t *testing.T) {
	origOptions := options
	defer func() { options = origOptions }()

	options = &types.Options{Logger: gologger.DefaultLogger}

	// Should return error on non-existent file to fail fast and prevent
	// silently running without expected profile extras
	err := processProfileExtras("/nonexistent/path/profile.yaml")
	require.Error(t, err, "non-existent file should return an error")
	require.Contains(t, err.Error(), "could not read profile extras")
}

func TestProcessProfileExtras_ExtraUnknownFields(t *testing.T) {
	origOptions := options
	defer func() { options = origOptions }()

	// Create a temp profile with many unknown fields
	tmpFile, err := os.CreateTemp("", "test-profile-extras-*.yaml")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString(`
id: extras-profile
name: Extras Profile
purpose: Test extra fields tolerance
description: Profile with many custom fields
custom-field-1: value1
custom-field-2: value2
organization: acme-corp
scan-owner: john@example.com
version: 2
tags:
  - cve
`)
	require.NoError(t, err)
	_ = tmpFile.Close()

	options = &types.Options{Logger: gologger.DefaultLogger}

	err = processProfileExtras(tmpFile.Name())
	require.NoError(t, err, "processProfileExtras should not return an error for a profile with extra unknown fields")

	// Known metadata fields should be extracted
	require.Equal(t, "extras-profile", options.ProfileID)
	require.Equal(t, "Extras Profile", options.ProfileName)
	require.Equal(t, "Test extra fields tolerance", options.ProfilePurpose)
	require.Equal(t, "Profile with many custom fields", options.ProfileDescription)

	// No errors, no secrets
	require.Empty(t, options.SecretsFile)
}

func TestCleanupTempFiles(t *testing.T) {
	// Create a temp file
	tmpFile, err := os.CreateTemp("", "test-cleanup-*.yaml")
	require.NoError(t, err)
	_ = tmpFile.Close()

	// Add to tempFiles list
	origTempFiles := tempFiles
	defer func() { tempFiles = origTempFiles }()

	tempFiles = []string{tmpFile.Name()}

	// Verify file exists
	_, err = os.Stat(tmpFile.Name())
	require.NoError(t, err)

	// Run cleanup
	cleanupTempFiles()

	// Verify file was removed
	_, err = os.Stat(tmpFile.Name())
	require.True(t, os.IsNotExist(err), "temp file should have been removed")
}
