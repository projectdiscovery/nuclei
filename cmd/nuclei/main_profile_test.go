package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestSanitizeTemplateProfileForMerge(t *testing.T) {
	options = &types.Options{}
	runtimeCleanupFns = nil

	profilePath := filepath.Join(t.TempDir(), "profile.yaml")
	require.NoError(t, os.WriteFile(profilePath, []byte(`id: demo
name: Demo Profile
purpose: Test
description: should-be-removed
list: |
  https://example.com
secrets:
  static:
    - type: header
      domains:
        - example.com
tags:
  - kev
`), 0o600))

	profileData, err := readTemplateProfileData(profilePath)
	require.NoError(t, err)

	sanitizedPath, cleanup, err := sanitizeTemplateProfileForMerge(profilePath, profileData)
	require.NoError(t, err)
	require.NotEmpty(t, sanitizedPath)
	if cleanup != nil {
		t.Cleanup(cleanup)
	}

	data, err := os.ReadFile(sanitizedPath)
	require.NoError(t, err)
	text := string(data)
	require.NotContains(t, text, "id:")
	require.NotContains(t, text, "name:")
	require.NotContains(t, text, "purpose:")
	require.NotContains(t, text, "description:")
	require.NotContains(t, text, "secrets:")
	require.Contains(t, text, "tags:")
	require.Contains(t, text, "list:")
}

func TestMaterializeInlineListTargets(t *testing.T) {
	options = &types.Options{}
	runtimeCleanupFns = nil

	profilePath := filepath.Join(t.TempDir(), "profile.yaml")
	require.NoError(t, os.WriteFile(profilePath, []byte(`list: |
  https://one.example
  https://two.example
`), 0o600))

	profileData, err := readTemplateProfileData(profilePath)
	require.NoError(t, err)

	cleanup, err := materializeInlineListTargets(profileData)
	require.NoError(t, err)
	require.NotEmpty(t, options.TargetsFilePath)
	if cleanup != nil {
		t.Cleanup(cleanup)
	}

	data, err := os.ReadFile(options.TargetsFilePath)
	require.NoError(t, err)
	require.Contains(t, string(data), "https://one.example")
	require.Contains(t, string(data), "https://two.example")
}

func TestMaterializeSingleLineInlineTarget(t *testing.T) {
	options = &types.Options{}
	runtimeCleanupFns = nil

	profilePath := filepath.Join(t.TempDir(), "profile.yaml")
	require.NoError(t, os.WriteFile(profilePath, []byte("list: https://single.example\n"), 0o600))

	profileData, err := readTemplateProfileData(profilePath)
	require.NoError(t, err)

	cleanup, err := materializeInlineListTargets(profileData)
	require.NoError(t, err)
	require.NotEmpty(t, options.TargetsFilePath)
	if cleanup != nil {
		t.Cleanup(cleanup)
	}

	data, err := os.ReadFile(options.TargetsFilePath)
	require.NoError(t, err)
	require.Equal(t, "https://single.example\n", string(data))
}

func TestMaterializeInlineSecretsFromProfile(t *testing.T) {
	options = &types.Options{}
	runtimeCleanupFns = nil

	profilePath := filepath.Join(t.TempDir(), "profile.yaml")
	require.NoError(t, os.WriteFile(profilePath, []byte(`secrets:
  static:
    - type: header
      domains:
        - example.com
      headers:
        - key: X-API-Key
          value: abc
`), 0o600))

	profileData, err := readTemplateProfileData(profilePath)
	require.NoError(t, err)

	cleanup, err := materializeInlineSecretsFromProfile(profileData)
	require.NoError(t, err)
	require.Len(t, options.SecretsFile, 1)
	if cleanup != nil {
		t.Cleanup(cleanup)
	}

	data, err := os.ReadFile(options.SecretsFile[0])
	require.NoError(t, err)
	require.Contains(t, string(data), "static:")
	require.Contains(t, string(data), "X-API-Key")
}
