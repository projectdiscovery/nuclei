package config

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func toAbs(p string) string {
	if runtime.GOOS == "windows" {
		return filepath.FromSlash("C:" + p)
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
