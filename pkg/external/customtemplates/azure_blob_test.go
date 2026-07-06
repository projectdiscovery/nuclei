package customtemplates

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// The Azure Download path validates blob names through safeJoinWithinDirectory.
// These tests cover that validation directly, mirroring the per-blob iteration
// in customTemplateAzureBlob.Download so we lock in the same allow/deny shape
// the runtime applies to server-controlled blob names.

func TestAzureSafeJoinRejectsTraversalBlobNames(t *testing.T) {
	downloadPath := t.TempDir()

	cases := []struct {
		name     string
		blobName string
	}{
		{"parent traversal", "../evil.yaml"},
		{"deep traversal", "a/b/../../../etc/evil.yaml"},
		{"bare dotdot", ".."},
		{"sibling prefix via dotdot", "../" + filepath.Base(downloadPath) + "-evil/template.yaml"},
		{"absolute escape via dotdot prefix", "../../etc/evil.yaml"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := safeJoinWithinDirectory(downloadPath, tc.blobName)
			require.Errorf(t, err, "blob name %q must be rejected", tc.blobName)
		})
	}
}

func TestAzureSafeJoinPreservesNestedBlobNames(t *testing.T) {
	downloadPath := t.TempDir()

	cases := []struct {
		name     string
		blobName string
		want     string
	}{
		{"flat", "template.yaml", filepath.Join(downloadPath, "template.yaml")},
		{"nested", "dir/sub/template.yaml", filepath.Join(downloadPath, "dir", "sub", "template.yaml")},
		{"sibling-basename in different dirs A", "alpha/template.yaml", filepath.Join(downloadPath, "alpha", "template.yaml")},
		{"sibling-basename in different dirs B", "beta/template.yaml", filepath.Join(downloadPath, "beta", "template.yaml")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := safeJoinWithinDirectory(downloadPath, tc.blobName)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}
