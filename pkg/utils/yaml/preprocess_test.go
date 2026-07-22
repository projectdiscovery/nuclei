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

// TestPreProcessRejectsIncludeOutsideAllowedDirs guards the include-path
// confinement: with -lfa disabled, an include resolving outside the including
// template's directory (and any template base dir) must be denied.
func TestPreProcessRejectsIncludeOutsideAllowedDirs(t *testing.T) {
	restoreSandboxState(t)

	templateDir := t.TempDir()
	outsideDir := t.TempDir()
	outsidePath := filepath.Join(outsideDir, "outside.yaml")
	require.NoError(t, os.WriteFile(outsidePath, []byte("secret: leaked"), 0o600))

	var err error
	require.NotPanics(t, func() {
		_, err = PreProcess([]byte(fmt.Sprintf("# !include:%s\nid: root\n", outsidePath)), filepath.Join(templateDir, "root.yaml"))
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "outside the templates directory")
}

// TestPreProcessRejectsHardLinkedInclude guards against hard-link smuggling: an
// include file that lives inside an allowed directory but is a hard link to
// content elsewhere must still be denied when -lfa is disabled.
func TestPreProcessRejectsHardLinkedInclude(t *testing.T) {
	restoreSandboxState(t)

	dir := t.TempDir()
	realPath := filepath.Join(dir, "real.yaml")
	require.NoError(t, os.WriteFile(realPath, []byte("secret: leaked"), 0o600))

	linkedPath := filepath.Join(dir, "linked.yaml")
	if err := os.Link(realPath, linkedPath); err != nil {
		t.Skipf("hard links not supported on this platform/filesystem: %v", err)
	}

	var err error
	require.NotPanics(t, func() {
		_, err = PreProcess([]byte(fmt.Sprintf("# !include:%s\nid: root\n", linkedPath)), filepath.Join(dir, "root.yaml"))
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "hard link")
}

func restoreStrictSyntax(t *testing.T) {
	t.Helper()

	previous := StrictSyntax
	StrictSyntax = false
	t.Cleanup(func() {
		StrictSyntax = previous
	})
}

// restoreSandboxState resets the package-level preprocessing knobs to their
// sandboxed defaults (strict syntax off, local file access denied, no template
// base dir) and restores the originals on cleanup so include-confinement tests
// are isolated from each other and from global state.
func restoreSandboxState(t *testing.T) {
	t.Helper()

	previousStrict := StrictSyntax
	previousLFA := AllowLocalFileAccess
	previousProvider := TemplateBaseDirProvider

	StrictSyntax = false
	AllowLocalFileAccess = false
	TemplateBaseDirProvider = nil

	t.Cleanup(func() {
		StrictSyntax = previousStrict
		AllowLocalFileAccess = previousLFA
		TemplateBaseDirProvider = previousProvider
	})
}
