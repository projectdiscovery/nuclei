package config

import (
	"os"
	"path/filepath"
	"testing"

	osutils "github.com/projectdiscovery/utils/os"
	"github.com/stretchr/testify/require"
)

func toAbs(p string) string {
	if osutils.IsWindows() {
		// Infer the drive letter from the Windows system path
		// SystemRoot or WINDIR typically points to something like "C:\Windows"
		systemRoot := os.Getenv("SystemRoot")
		if systemRoot == "" {
			systemRoot = os.Getenv("WINDIR")
		}
		// Extract volume name (e.g., "C:") from the system path
		volumeName := filepath.VolumeName(systemRoot)
		if volumeName == "" {
			// Fallback to C: if we can't determine the volume
			volumeName = "C:"
		}
		return filepath.FromSlash(volumeName + p)
	}
	return filepath.FromSlash(p)
}

func TestIsTemplate(t *testing.T) {
	tests := []struct {
		name    string
		fpath   string
		rootDir string
		want    bool
	}{
		{
			name:    "valid template",
			fpath:   "dns/cname.yaml",
			rootDir: "",
			want:    true,
		},
		{
			name:    "excluded directory relative",
			fpath:   "helpers/data.txt",
			rootDir: "",
			want:    false,
		},
		{
			name:    "excluded directory .git",
			fpath:   ".git/config",
			rootDir: "",
			want:    false,
		},
		{
			name:    "absolute path with excluded parent dir (bug fix)",
			fpath:   toAbs("/path/to/somewhere/that/has/helpers/dir/nuclei/nuclei-templates/dns/cname.yaml"),
			rootDir: toAbs("/path/to/somewhere/that/has/helpers/dir/nuclei/nuclei-templates"),
			want:    true,
		},
		{
			name:    "absolute path with excluded dir inside root",
			fpath:   toAbs("/path/to/somewhere/that/has/helpers/dir/nuclei/nuclei-templates/helpers/data.txt"),
			rootDir: toAbs("/path/to/somewhere/that/has/helpers/dir/nuclei/nuclei-templates"),
			want:    false,
		},
		{
			name:    "absolute path without root (skip check)",
			fpath:   toAbs("/opt/helpers/foo.yaml"),
			rootDir: "",
			want:    true,
		},
		{
			name:    "valid template with different extension",
			fpath:   "dns/cname.json",
			rootDir: "",
			want:    true,
		},
		{
			name:    "invalid extension",
			fpath:   "dns/cname.txt",
			rootDir: "",
			want:    false,
		},
		{
			name:    "excluded config file",
			fpath:   "cves.json",
			rootDir: "",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsTemplateWithRoot(tt.fpath, tt.rootDir)
			require.Equal(t, tt.want, got, "IsTemplateWithRoot(%q, %q)", tt.fpath, tt.rootDir)
		})
	}
}

func TestGetNucleiTemplatesIndexIncludesCustomDirSiblingPrefix(t *testing.T) {
	tmpDir := t.TempDir()
	cfgDir := t.TempDir()

	oldConfigDir := DefaultConfig.GetConfigDir()
	oldTemplatesDir := DefaultConfig.TemplatesDirectory
	DefaultConfig.SetConfigDir(cfgDir)
	DefaultConfig.SetTemplatesDir(tmpDir)
	t.Cleanup(func() {
		DefaultConfig.SetConfigDir(oldConfigDir)
		DefaultConfig.SetTemplatesDir(oldTemplatesDir)
	})

	customGitHubDir := filepath.Join(tmpDir, "github")
	require.NoError(t, os.MkdirAll(customGitHubDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(customGitHubDir, "custom-template.yaml"), []byte(`id: custom-template
info:
  name: Custom Template
  author: test
  severity: info`), 0644))

	siblingDir := filepath.Join(tmpDir, "github-evil")
	require.NoError(t, os.MkdirAll(siblingDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(siblingDir, "sibling-template.yaml"), []byte(`id: sibling-template
info:
  name: Sibling Template
  author: test
  severity: info`), 0644))

	index, err := GetNucleiTemplatesIndex()
	require.NoError(t, err)
	require.NotContains(t, index, "custom-template", "custom template directory should be excluded")
	require.Contains(t, index, "sibling-template", "custom directory sibling prefix should be indexed")
}
