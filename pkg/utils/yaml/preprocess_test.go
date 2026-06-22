package yaml

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPreProcessIncludesFileAtStartOfData(t *testing.T) {
	restoreStrictSyntax(t)

	dir := t.TempDir()
	includedPath := filepath.Join(dir, "included.yaml")
	require.NoError(t, os.WriteFile(includedPath, []byte("alpha: one\nbeta: two"), 0o600))

	var (
		output []byte
		err    error
	)
	require.NotPanics(t, func() {
		output, err = PreProcess([]byte(fmt.Sprintf("# !include:%s\nroot: true\n", includedPath)))
	})
	require.NoError(t, err)
	require.NotContains(t, string(output), "# !include:")
	require.Contains(t, string(output), "alpha: one\nbeta: two")
	require.Contains(t, string(output), "root: true")
}

func TestPreProcessRejectsCircularInclude(t *testing.T) {
	restoreStrictSyntax(t)

	dir := t.TempDir()
	templatePath := filepath.Join(dir, "self.yaml")
	template := []byte(fmt.Sprintf("# !include:%s\nid: self\n", templatePath))
	require.NoError(t, os.WriteFile(templatePath, template, 0o600))

	var err error
	require.NotPanics(t, func() {
		_, err = PreProcess(template)
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "circular include")
}

func TestPreProcessRejectsExcessiveIncludeDepth(t *testing.T) {
	restoreStrictSyntax(t)

	dir := t.TempDir()
	paths := make([]string, 40)
	for i := range paths {
		paths[i] = filepath.Join(dir, fmt.Sprintf("include-%02d.yaml", i))
	}
	for i, path := range paths {
		content := fmt.Sprintf("id: include-%02d\n", i)
		if i < len(paths)-1 {
			content = fmt.Sprintf("# !include:%s\n%s", paths[i+1], content)
		}
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	}

	_, err := PreProcess([]byte(fmt.Sprintf("# !include:%s\nid: root\n", paths[0])))
	require.Error(t, err)
	require.Contains(t, err.Error(), "maximum include depth")
}

func restoreStrictSyntax(t *testing.T) {
	t.Helper()

	previous := StrictSyntax
	StrictSyntax = false
	t.Cleanup(func() {
		StrictSyntax = previous
	})
}
