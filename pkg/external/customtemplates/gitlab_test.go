package customtemplates

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSafeProjectOutputPathRejectsTraversal(t *testing.T) {
	location := t.TempDir()

	cases := []struct {
		name        string
		projectPath string
	}{
		{"parent traversal", "../etc"},
		{"deep traversal", "a/b/../../../etc"},
		{"empty base loop via dotdot", ".."},
		{"absolute escape via dotdot", "../" + filepath.Base(location) + "-evil"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := safeProjectOutputPath(location, tc.projectPath)
			require.Error(t, err, "expected %q to be rejected", tc.projectPath)
		})
	}
}

func TestSafeProjectOutputPathAllowsExpectedShape(t *testing.T) {
	location := t.TempDir()
	projectPath := "owner-foo/repo-bar"
	got, err := safeProjectOutputPath(location, projectPath)
	require.NoError(t, err)
	require.Equal(t, filepath.Join(location, projectPath), got)
}

func TestSafeProjectFileOutputPathPreservesNestedStructure(t *testing.T) {
	projectDir := t.TempDir()

	// Two files in different subdirectories with the same basename must
	// resolve to two different output paths so they don't clobber each other
	// (regression test for the previous flatten-via-basename behaviour).
	pathA := "alpha/template.yaml"
	pathB := "beta/template.yaml"

	gotA, err := safeProjectFileOutputPath(projectDir, pathA)
	require.NoError(t, err)
	gotB, err := safeProjectFileOutputPath(projectDir, pathB)
	require.NoError(t, err)
	require.NotEqual(t, gotA, gotB, "nested files with identical basenames must not collide")

	require.Equal(t, filepath.Join(projectDir, "alpha", "template.yaml"), gotA)
	require.Equal(t, filepath.Join(projectDir, "beta", "template.yaml"), gotB)
}

func TestSafeProjectFileOutputPathRejectsTraversal(t *testing.T) {
	projectDir := t.TempDir()

	cases := []string{
		"../escape.yaml",
		"sub/../../escape.yaml",
		"sub/sub2/../../../escape.yaml",
	}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			_, err := safeProjectFileOutputPath(projectDir, c)
			require.Error(t, err)
		})
	}
}
