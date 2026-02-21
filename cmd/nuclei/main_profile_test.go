package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestSanitizeTemplateProfileForMerge(t *testing.T) {
	dir := t.TempDir()
	profilePath := filepath.Join(dir, "profile.yaml")
	content := `id: demo
name: Demo Profile
purpose: test
list: hosts.txt
tags: ["cve"]
`
	require.NoError(t, os.WriteFile(profilePath, []byte(content), 0o644))

	newPath, cleanup, err := sanitizeTemplateProfileForMerge(profilePath)
	require.NoError(t, err)
	if cleanup != nil {
		defer cleanup()
	}
	require.NotEqual(t, profilePath, newPath)

	data, err := os.ReadFile(newPath)
	require.NoError(t, err)
	text := string(data)
	require.NotContains(t, text, "id:")
	require.NotContains(t, text, "name:")
	require.Contains(t, text, "list: hosts.txt")
}

func TestMaterializeInlineListTargets(t *testing.T) {
	prev := options
	options = &types.Options{}
	defer func() { options = prev }()

	options.TargetsFilePath = "https://a.example\nhttps://b.example"
	require.NoError(t, materializeInlineListTargets())
	require.NotContains(t, options.TargetsFilePath, "\n")

	data, err := os.ReadFile(options.TargetsFilePath)
	require.NoError(t, err)
	require.Contains(t, string(data), "https://a.example")
	require.Contains(t, string(data), "https://b.example")
}
