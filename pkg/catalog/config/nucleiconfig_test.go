package config

import (
	"path/filepath"
	"testing"
)

func TestIsCustomTemplateUsesPathBoundaries(t *testing.T) {
	templatesDir := filepath.Join(t.TempDir(), "nuclei-templates")
	cfg := &Config{}
	cfg.SetTemplatesDir(templatesDir)

	tests := []struct {
		name         string
		templatePath string
		want         bool
	}{
		{
			name:         "official template",
			templatePath: filepath.Join(templatesDir, "http", "test.yaml"),
			want:         false,
		},
		{
			name:         "official template sibling prefix",
			templatePath: filepath.Join(templatesDir+"-evil", "test.yaml"),
			want:         true,
		},
		{
			name:         "custom template",
			templatePath: filepath.Join(cfg.CustomGitHubTemplatesDirectory, "owner", "repo", "test.yaml"),
			want:         true,
		},
		{
			name:         "custom template sibling prefix",
			templatePath: filepath.Join(cfg.CustomGitHubTemplatesDirectory+"-evil", "test.yaml"),
			want:         false,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			got := cfg.IsCustomTemplate(testCase.templatePath)
			if got != testCase.want {
				t.Fatalf("expected %v, got %v", testCase.want, got)
			}
		})
	}
}
