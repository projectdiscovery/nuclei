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
		output, err = PreProcess([]byte(fmt.Sprintf("# !include:%s\nroot: true\n", includedPath)), filepath.Join(dir, "root.yaml"))
	})
	require.NoError(t, err)
	require.NotContains(t, string(output), "# !include:")
	require.Contains(t, string(output), "alpha: one\nbeta: two")
	require.Contains(t, string(output), "root: true")
}

func TestPreProcessExpandsRepeatedIncludeWithPerOccurrenceIndentation(t *testing.T) {
	restoreStrictSyntax(t)

	dir := t.TempDir()
	childPath := filepath.Join(dir, "child.yaml")
	require.NoError(t, os.WriteFile(childPath, []byte("key: value\nnested: true"), 0o600))

	// The same include directive appears twice at different indentation levels.
	// Each occurrence must be expanded using its own offset/indentation.
	data := []byte(fmt.Sprintf("root:\n  # !include:%s\nother:\n      # !include:%s\n", childPath, childPath))

	var (
		output []byte
		err    error
	)
	require.NotPanics(t, func() {
		output, err = PreProcess(data, filepath.Join(dir, "root.yaml"))
	})
	require.NoError(t, err)

	got := string(output)
	require.NotContains(t, got, "# !include:")
	require.Contains(t, got, "root:\n  key: value\n  nested: true")
	require.Contains(t, got, "other:\n      key: value\n      nested: true")
}

func TestPreProcessRejectsCircularInclude(t *testing.T) {
	restoreStrictSyntax(t)

	dir := t.TempDir()
	templatePath := filepath.Join(dir, "self.yaml")
	template := []byte(fmt.Sprintf("# !include:%s\nid: self\n", templatePath))
	require.NoError(t, os.WriteFile(templatePath, template, 0o600))

	var err error
	require.NotPanics(t, func() {
		_, err = PreProcess(template, templatePath)
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

	_, err := PreProcess([]byte(fmt.Sprintf("# !include:%s\nid: root\n", paths[0])), filepath.Join(dir, "root.yaml"))
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
