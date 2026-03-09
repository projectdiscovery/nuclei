package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/authprovider/authx"
	"github.com/stretchr/testify/require"
)

func TestPrepareConfigFileForMerge_StripsProfileMetadataAndExtractsSecrets(t *testing.T) {
	t.Cleanup(cleanupGeneratedFiles)

	configPath := filepath.Join(t.TempDir(), "profile.yaml")
	config := `id: cloud-profile
name: Cloud Scan
purpose: Shared scan settings
description: Example profile
tags:
  - kev
secrets:
  static:
    - type: Header
      domains:
        - api.projectdiscovery.io
      headers:
        - key: Authorization
          value: Bearer test-token
`
	require.NoError(t, os.WriteFile(configPath, []byte(config), 0o644))

	prepared, err := prepareConfigFileForMerge(configPath)
	require.NoError(t, err)
	require.NotEqual(t, configPath, prepared.Path)
	require.Len(t, prepared.SecretsFiles, 1)

	preparedConfig, err := os.ReadFile(prepared.Path)
	require.NoError(t, err)
	require.Contains(t, string(preparedConfig), "tags:")
	require.NotContains(t, string(preparedConfig), "secrets:")
	require.NotContains(t, string(preparedConfig), "purpose:")

	authData, err := authx.GetAuthDataFromFile(prepared.SecretsFiles[0])
	require.NoError(t, err)
	require.Len(t, authData.Secrets, 1)
	require.Equal(t, "Authorization", authData.Secrets[0].Headers[0].Key)
}

func TestPrepareConfigFileForMerge_LeavesPlainConfigUntouched(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	config := `tags:
  - cves
rate-limit: 50
`
	require.NoError(t, os.WriteFile(configPath, []byte(config), 0o644))

	prepared, err := prepareConfigFileForMerge(configPath)
	require.NoError(t, err)
	require.Equal(t, configPath, prepared.Path)
	require.Empty(t, prepared.SecretsFiles)
}

func TestPrepareConfigFileForMerge_RejectsInvalidEmbeddedSecrets(t *testing.T) {
	t.Cleanup(cleanupGeneratedFiles)

	configPath := filepath.Join(t.TempDir(), "profile.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte("secrets: invalid\n"), 0o644))

	_, err := prepareConfigFileForMerge(configPath)
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "embedded secrets"))
}
