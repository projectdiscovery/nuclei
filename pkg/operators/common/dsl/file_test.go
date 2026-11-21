package dsl

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/projectdiscovery/govaluate"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestFileHelperRegistered(t *testing.T) {
	_, ok := HelperFunctions["file"]
	require.True(t, ok, "file helper must be registered in HelperFunctions")
}

func TestFileHelperResolvesRelativeAgainstTemplateNotCwd(t *testing.T) {
	_, templatesDir, templatePath := setupFileHelperSandbox(t)

	templateDir := filepath.Dir(templatePath)
	require.NoError(t, os.WriteFile(filepath.Join(templateDir, "payload.txt"), []byte("template-local"), 0o600))

	originalWd, err := os.Getwd()
	require.NoError(t, err)
	unrelated := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(unrelated, "payload.txt"), []byte("cwd-local"), 0o600))
	require.NoError(t, os.Chdir(unrelated))
	t.Cleanup(func() { _ = os.Chdir(originalWd) })

	ctx := &FileLoadContext{
		Options:      &types.Options{},
		TemplatePath: templatePath,
		Catalog:      disk.NewCatalog(templatesDir),
	}

	var (
		got     string
		evalErr error
	)
	WithFileLoadContext(ctx, func() {
		got, evalErr = evalFile(t, `file("payload.txt")`, nil)
	})
	require.NoError(t, evalErr)
	require.Equal(t, "template-local", got, "must resolve relative to template dir, not CWD")
}

func TestFileHelperRejectsEmptyPath(t *testing.T) {
	home, templatesDir, templatePath := setupFileHelperSandbox(t)
	_ = home

	ctx := &FileLoadContext{
		Options:      &types.Options{},
		TemplatePath: templatePath,
		Catalog:      disk.NewCatalog(templatesDir),
	}

	var got error
	WithFileLoadContext(ctx, func() {
		_, got = evalFile(t, `file("")`, nil)
	})
	require.Error(t, got)
	require.Contains(t, got.Error(), "must not be empty")
}

func TestFileHelperReadsRelativeToTemplateDir(t *testing.T) {
	_, templatesDir, templatePath := setupFileHelperSandbox(t)

	templateDir := filepath.Dir(templatePath)
	payloadPath := filepath.Join(templateDir, "payload.bin")
	require.NoError(t, os.WriteFile(payloadPath, []byte{0x00, 0x01, 0xff, 'A'}, 0o600))

	ctx := &FileLoadContext{
		Options:      &types.Options{},
		TemplatePath: templatePath,
		Catalog:      disk.NewCatalog(templatesDir),
	}

	var (
		got string
		err error
	)
	WithFileLoadContext(ctx, func() {
		got, err = evalFile(t, `file("payload.bin")`, nil)
	})
	require.NoError(t, err)
	require.Equal(t, string([]byte{0x00, 0x01, 0xff, 'A'}), got)
}

func TestFileHelperReadsFromNucleiTemplatesDirectory(t *testing.T) {
	_, templatesDir, templatePath := setupFileHelperSandbox(t)

	helperPath := filepath.Join(templatesDir, "shared-payload.txt")
	require.NoError(t, os.WriteFile(helperPath, []byte("from-templates-dir"), 0o600))

	// Template lives outside templatesDir; rule 1 still allows templates-dir helpers.
	outsideHome := t.TempDir()
	outsideTemplate := filepath.Join(outsideHome, "template.yaml")
	require.NoError(t, os.WriteFile(outsideTemplate, []byte("id: x\n"), 0o600))

	ctx := &FileLoadContext{
		Options:      &types.Options{},
		TemplatePath: outsideTemplate,
		Catalog:      disk.NewCatalog(templatesDir),
	}
	_ = templatePath

	var (
		got string
		err error
	)
	WithFileLoadContext(ctx, func() {
		got, err = evalFile(t, fileExpr(helperPath), nil)
	})
	require.NoError(t, err)
	require.Equal(t, "from-templates-dir", got)
}

func TestFileHelperDeniesPathOutsideSandbox(t *testing.T) {
	_, templatesDir, templatePath := setupFileHelperSandbox(t)

	secretDir := t.TempDir()
	secretPath := filepath.Join(secretDir, "secret.txt")
	require.NoError(t, os.WriteFile(secretPath, []byte("top-secret"), 0o600))

	ctx := &FileLoadContext{
		Options:      &types.Options{},
		TemplatePath: templatePath,
		Catalog:      disk.NewCatalog(templatesDir),
	}

	var got error
	WithFileLoadContext(ctx, func() {
		_, got = evalFile(t, fileExpr(secretPath), nil)
	})
	require.Error(t, got)
	require.True(t, strings.Contains(got.Error(), "denied") || strings.Contains(got.Error(), "could not load"), got.Error())
}

func TestFileHelperDeniesTraversalOutsideTemplateDir(t *testing.T) {
	home, templatesDir, templatePath := setupFileHelperSandbox(t)

	outsideHelper := filepath.Join(home, "outside.txt")
	require.NoError(t, os.WriteFile(outsideHelper, []byte("escaped"), 0o600))

	ctx := &FileLoadContext{
		Options:      &types.Options{},
		TemplatePath: templatePath,
		Catalog:      disk.NewCatalog(templatesDir),
	}

	var got error
	WithFileLoadContext(ctx, func() {
		_, got = evalFile(t, `file("../outside.txt")`, nil)
	})
	require.Error(t, got)
}

func TestFileHelperDeniesSiblingPrefixTemplatesDir(t *testing.T) {
	home, templatesDir, templatePath := setupFileHelperSandbox(t)

	evilDir := filepath.Join(home, "nuclei-templates-evil")
	require.NoError(t, os.MkdirAll(evilDir, 0o755))
	evilFile := filepath.Join(evilDir, "payloads.txt")
	require.NoError(t, os.WriteFile(evilFile, []byte("evil"), 0o600))

	ctx := &FileLoadContext{
		Options:      &types.Options{},
		TemplatePath: templatePath,
		Catalog:      disk.NewCatalog(templatesDir),
	}

	var got error
	WithFileLoadContext(ctx, func() {
		_, got = evalFile(t, fileExpr(evilFile), nil)
	})
	require.Error(t, got)
}

func TestFileHelperDeniesSymlinkToOutside(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is not reliable on all Windows runners")
	}

	_, templatesDir, templatePath := setupFileHelperSandbox(t)

	outsideDir := filepath.Join(filepath.Dir(templatesDir), "outside")
	require.NoError(t, os.MkdirAll(outsideDir, 0o755))
	outsideFile := filepath.Join(outsideDir, "secret.txt")
	require.NoError(t, os.WriteFile(outsideFile, []byte("secret"), 0o600))

	linkPath := filepath.Join(templatesDir, "linked-secret.txt")
	require.NoError(t, os.Symlink(outsideFile, linkPath))

	ctx := &FileLoadContext{
		Options:      &types.Options{},
		TemplatePath: templatePath,
		Catalog:      disk.NewCatalog(templatesDir),
	}

	var got error
	WithFileLoadContext(ctx, func() {
		_, got = evalFile(t, fileExpr(linkPath), nil)
	})
	require.Error(t, got)
}

func TestFileHelperDeniesHardLink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hard links are not exercised on Windows")
	}

	_, templatesDir, templatePath := setupFileHelperSandbox(t)

	outsideDir := t.TempDir()
	outsideFile := filepath.Join(outsideDir, "secret.txt")
	require.NoError(t, os.WriteFile(outsideFile, []byte("secret"), 0o600))

	linkPath := filepath.Join(templatesDir, "hardlinked-secret.txt")
	if err := os.Link(outsideFile, linkPath); err != nil {
		t.Skipf("hard link not supported: %v", err)
	}

	ctx := &FileLoadContext{
		Options:      &types.Options{},
		TemplatePath: templatePath,
		Catalog:      disk.NewCatalog(templatesDir),
	}

	var got error
	WithFileLoadContext(ctx, func() {
		_, got = evalFile(t, fileExpr(linkPath), nil)
	})
	require.Error(t, got)
	require.Contains(t, got.Error(), "hard link")
}

func TestFileHelperDeniesDirectory(t *testing.T) {
	_, templatesDir, templatePath := setupFileHelperSandbox(t)

	dirPath := filepath.Join(filepath.Dir(templatePath), "subdir")
	require.NoError(t, os.MkdirAll(dirPath, 0o755))

	ctx := &FileLoadContext{
		Options:      &types.Options{},
		TemplatePath: templatePath,
		Catalog:      disk.NewCatalog(templatesDir),
	}

	var got error
	WithFileLoadContext(ctx, func() {
		_, got = evalFile(t, `file("subdir")`, nil)
	})
	require.Error(t, got)
	require.Contains(t, got.Error(), "not a regular file")
}

func TestFileHelperAllowLocalFileAccessReadsAbsolutePath(t *testing.T) {
	_, templatesDir, templatePath := setupFileHelperSandbox(t)

	secretDir := t.TempDir()
	secretPath := filepath.Join(secretDir, "secret.txt")
	require.NoError(t, os.WriteFile(secretPath, []byte("allowed-with-lfa"), 0o600))

	ctx := &FileLoadContext{
		Options: &types.Options{
			AllowLocalFileAccess: true,
		},
		TemplatePath: templatePath,
		Catalog:      disk.NewCatalog(templatesDir),
	}

	var (
		got string
		err error
	)
	WithFileLoadContext(ctx, func() {
		got, err = evalFile(t, fileExpr(secretPath), nil)
	})
	require.NoError(t, err)
	require.Equal(t, "allowed-with-lfa", got)
}

func TestFileHelperRejectsOversizedContent(t *testing.T) {
	_, templatesDir, templatePath := setupFileHelperSandbox(t)

	ctx := &FileLoadContext{
		Options: &types.Options{
			LoadHelperFileFunction: func(helperFile, _ string, _ catalog.Catalog) (io.ReadCloser, error) {
				return io.NopCloser(&hugeReader{n: maxFileHelperSize + 1}), nil
			},
		},
		TemplatePath: templatePath,
		Catalog:      disk.NewCatalog(templatesDir),
	}

	var got error
	WithFileLoadContext(ctx, func() {
		_, got = evalFile(t, `file("huge.bin")`, nil)
	})
	require.Error(t, got)
	require.Contains(t, got.Error(), "exceeds maximum size")
}

func TestFileHelperCachesPerContext(t *testing.T) {
	_, templatesDir, templatePath := setupFileHelperSandbox(t)

	templateDir := filepath.Dir(templatePath)
	payloadPath := filepath.Join(templateDir, "cached.txt")
	require.NoError(t, os.WriteFile(payloadPath, []byte("v1"), 0o600))

	var opens int
	ctx := &FileLoadContext{
		Options: &types.Options{
			LoadHelperFileFunction: func(helperFile, tpl string, cat catalog.Catalog) (io.ReadCloser, error) {
				opens++
				return (&types.Options{}).LoadHelperFile(helperFile, tpl, cat)
			},
		},
		TemplatePath: templatePath,
		Catalog:      disk.NewCatalog(templatesDir),
	}

	WithFileLoadContext(ctx, func() {
		got1, err := evalFile(t, `file("cached.txt")`, nil)
		require.NoError(t, err)
		require.Equal(t, "v1", got1)

		got2, err := evalFile(t, `file("cached.txt")`, nil)
		require.NoError(t, err)
		require.Equal(t, "v1", got2)
	})
	require.Equal(t, 1, opens, "second file() call should use cache")
}

func TestFileHelperContextDoesNotLeakAcrossGoroutines(t *testing.T) {
	_, templatesDir, templatePath := setupFileHelperSandbox(t)

	templateDir := filepath.Dir(templatePath)
	require.NoError(t, os.WriteFile(filepath.Join(templateDir, "ok.txt"), []byte("ok"), 0o600))

	allowedCtx := &FileLoadContext{
		Options:      &types.Options{},
		TemplatePath: templatePath,
		Catalog:      disk.NewCatalog(templatesDir),
	}

	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})

	go func() {
		defer close(done)
		WithFileLoadContext(allowedCtx, func() {
			_, err := evalFile(t, `file("ok.txt")`, nil)
			require.NoError(t, err)
			close(started)
			<-release
		})
	}()

	<-started
	_, errNoCtx := evalFile(t, `file("ok.txt")`, nil)
	close(release)
	<-done

	require.Error(t, errNoCtx, "goroutine without context must not observe another goroutine's sandbox")
	require.Contains(t, errNoCtx.Error(), "no template sandbox context")
}

type hugeReader struct {
	n int64
	i int64
}

func (h *hugeReader) Read(p []byte) (int, error) {
	if h.i >= h.n {
		return 0, io.EOF
	}
	remaining := h.n - h.i
	if int64(len(p)) > remaining {
		p = p[:remaining]
	}
	for i := range p {
		p[i] = 'A'
	}
	h.i += int64(len(p))
	return len(p), nil
}

func setupFileHelperSandbox(t *testing.T) (home, templatesDir, templatePath string) {
	t.Helper()

	home = t.TempDir()
	// os.UserHomeDir (used by folderutil.HomeDirOrDefault) reads HOME on Unix and
	// USERPROFILE on Windows; set both so sandbox rule-2 home checks are portable.
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	templatesDir = filepath.Join(home, "nuclei-templates")
	templateDir := filepath.Join(home, "custom-templates")
	for _, dir := range []string{templatesDir, templateDir} {
		require.NoError(t, os.MkdirAll(dir, 0o755))
	}

	oldTemplatesDir := config.DefaultConfig.TemplatesDirectory
	config.DefaultConfig.SetTemplatesDir(templatesDir)
	t.Cleanup(func() {
		config.DefaultConfig.SetTemplatesDir(oldTemplatesDir)
	})

	templatePath = filepath.Join(templateDir, "template.yaml")
	require.NoError(t, os.WriteFile(templatePath, []byte("id: file-helper\n"), 0o600))
	return home, templatesDir, templatePath
}

func evalFile(t *testing.T, expression string, values map[string]interface{}) (string, error) {
	t.Helper()
	compiled, err := govaluate.NewEvaluableExpressionWithFunctions(expression, HelperFunctions)
	require.NoError(t, err, "expression must compile")
	result, err := compiled.Evaluate(values)
	if err != nil {
		return "", err
	}
	return types.ToString(result), nil
}

// fileExpr builds a file() call with a slash-normalized path so Windows
// backslashes are not treated as string escapes by the expression parser.
func fileExpr(path string) string {
	return `file("` + filepath.ToSlash(path) + `")`
}
