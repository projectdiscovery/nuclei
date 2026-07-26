package dsl

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	folderutil "github.com/projectdiscovery/utils/folder"
	"github.com/stretchr/testify/require"
)

// TestFileHelperSandboxDeniesUntrustedPaths exercises path variants that must
// remain unreadable under the default helper-file policy.
func TestFileHelperSandboxDeniesUntrustedPaths(t *testing.T) {
	home, templatesDir, templatePath := setupFileHelperSandbox(t)
	templateDir := filepath.Dir(templatePath)

	outsideDir := t.TempDir()
	outsideFile := filepath.Join(outsideDir, "secret.txt")
	require.NoError(t, os.WriteFile(outsideFile, []byte("outside-secret"), 0o600))

	homeSibling := filepath.Join(home, "sibling-secret.txt")
	require.NoError(t, os.WriteFile(homeSibling, []byte("home-sibling"), 0o600))

	prefixSiblingDir := filepath.Join(home, "nuclei-templatesX")
	require.NoError(t, os.MkdirAll(prefixSiblingDir, 0o755))
	prefixSiblingFile := filepath.Join(prefixSiblingDir, "payload.txt")
	require.NoError(t, os.WriteFile(prefixSiblingFile, []byte("prefix-sibling"), 0o600))

	nestedOutside := filepath.Join(home, "nested", "deep", "secret.txt")
	require.NoError(t, os.MkdirAll(filepath.Dir(nestedOutside), 0o755))
	require.NoError(t, os.WriteFile(nestedOutside, []byte("nested-secret"), 0o600))

	ctx := &FileLoadContext{
		Options:      &types.Options{},
		TemplatePath: templatePath,
		Catalog:      disk.NewCatalog(templatesDir),
	}

	cases := []struct {
		name string
		expr string
	}{
		{name: "absolute_outside_home", expr: fileExpr(outsideFile)},
		{name: "absolute_under_home_but_outside_template_and_templates_dir", expr: fileExpr(homeSibling)},
		{name: "absolute_prefix_sibling_of_templates_dir", expr: fileExpr(prefixSiblingFile)},
		{name: "absolute_nested_under_home_outside_template_tree", expr: fileExpr(nestedOutside)},
		{name: "relative_parent", expr: `file("../sibling-secret.txt")`},
		{name: "relative_parent_chain", expr: `file("../../sibling-secret.txt")`},
		{name: "relative_dotdot_via_subdir", expr: `file("payloads/../../sibling-secret.txt")`},
		{name: "relative_dot_slash_parent", expr: `file("./../sibling-secret.txt")`},
		{name: "relative_nested_escape", expr: `file("a/b/../../../sibling-secret.txt")`},
		{name: "relative_to_nested_outside", expr: `file("../nested/deep/secret.txt")`},
		{name: "whitespace_only_path", expr: `file("   ")`},
		{name: "dot_path", expr: `file(".")`},
		{name: "dotdot_path", expr: `file("..")`},
		{name: "empty_components", expr: `file("////")`},
	}

	// Also deny reading the template directory itself and templates dir as paths.
	cases = append(cases,
		struct {
			name string
			expr string
		}{name: "template_directory", expr: fileExpr(templateDir)},
		struct {
			name string
			expr string
		}{name: "templates_directory", expr: fileExpr(templatesDir)},
	)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got error
			WithFileLoadContext(ctx, func() {
				_, got = evalFile(t, tc.expr, nil)
			})
			require.Error(t, got, "expression %s must fail", tc.expr)
			require.NotContains(t, got.Error(), "outside-secret")
			require.NotContains(t, got.Error(), "home-sibling")
			require.NotContains(t, got.Error(), "prefix-sibling")
			require.NotContains(t, got.Error(), "nested-secret")
		})
	}
}

func TestFileHelperRejectsMissingSandboxContext(t *testing.T) {
	_, templatesDir, templatePath := setupFileHelperSandbox(t)
	templateDir := filepath.Dir(templatePath)
	require.NoError(t, os.WriteFile(filepath.Join(templateDir, "ok.txt"), []byte("ok"), 0o600))

	_, err := evalFile(t, `file("ok.txt")`, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no template sandbox context")

	ctxNilOptions := &FileLoadContext{
		Options:      nil,
		TemplatePath: templatePath,
		Catalog:      disk.NewCatalog(templatesDir),
	}
	var got error
	WithFileLoadContext(ctxNilOptions, func() {
		_, got = evalFile(t, `file("ok.txt")`, nil)
	})
	require.Error(t, got)
	require.Contains(t, got.Error(), "no template sandbox context")
}

func TestFileHelperRejectsWrongArity(t *testing.T) {
	_, templatesDir, templatePath := setupFileHelperSandbox(t)
	ctx := &FileLoadContext{
		Options:      &types.Options{},
		TemplatePath: templatePath,
		Catalog:      disk.NewCatalog(templatesDir),
	}

	var got error
	WithFileLoadContext(ctx, func() {
		_, got = evalFile(t, `file("a","b")`, nil)
	})
	require.Error(t, got)
}

func TestFileHelperRejectsTemplateAtHomeRootExpandingHome(t *testing.T) {
	home, templatesDir, _ := setupFileHelperSandbox(t)

	// Place the template directly in $HOME so templateDir == home. Rule 2 must
	// refuse expanding the allowed tree to the entire home directory.
	homeTemplate := filepath.Join(home, "template.yaml")
	require.NoError(t, os.WriteFile(homeTemplate, []byte("id: home-root\n"), 0o600))
	homeSecret := filepath.Join(home, "ssh-keys.txt")
	require.NoError(t, os.WriteFile(homeSecret, []byte("id-rsa-material"), 0o600))

	// Sanity-check the sandbox home override is what GetValidAbsPath will see.
	require.Equal(t, filepath.Clean(home), filepath.Clean(folderutil.HomeDirOrDefault("")),
		"sandbox home override must be active for this assertion")

	ctx := &FileLoadContext{
		Options:      &types.Options{},
		TemplatePath: homeTemplate,
		Catalog:      disk.NewCatalog(templatesDir),
	}

	var got error
	WithFileLoadContext(ctx, func() {
		_, got = evalFile(t, fileExpr(homeSecret), nil)
	})
	require.Error(t, got)
	require.NotContains(t, got.Error(), "id-rsa-material")
}

func TestFileHelperAllowsNormalizedRelativeWithinTemplateDir(t *testing.T) {
	_, templatesDir, templatePath := setupFileHelperSandbox(t)
	templateDir := filepath.Dir(templatePath)
	require.NoError(t, os.MkdirAll(filepath.Join(templateDir, "payloads"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(templateDir, "payloads", "data.txt"), []byte("in-sandbox"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(templateDir, "root.txt"), []byte("root-payload"), 0o600))

	ctx := &FileLoadContext{
		Options:      &types.Options{},
		TemplatePath: templatePath,
		Catalog:      disk.NewCatalog(templatesDir),
	}

	cases := []struct {
		name string
		expr string
		want string
	}{
		{name: "plain_relative", expr: `file("root.txt")`, want: "root-payload"},
		{name: "dot_slash", expr: `file("./root.txt")`, want: "root-payload"},
		{name: "child_relative", expr: `file("payloads/data.txt")`, want: "in-sandbox"},
		{name: "dotdot_stays_inside", expr: `file("payloads/../root.txt")`, want: "root-payload"},
		{name: "redundant_dots", expr: `file("./payloads/./data.txt")`, want: "in-sandbox"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var (
				got string
				err error
			)
			WithFileLoadContext(ctx, func() {
				got, err = evalFile(t, tc.expr, nil)
			})
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestFileHelperNestedContextRestoresOuterSandbox(t *testing.T) {
	_, templatesDir, templatePath := setupFileHelperSandbox(t)

	secretDir := t.TempDir()
	secretPath := filepath.Join(secretDir, "secret.txt")
	require.NoError(t, os.WriteFile(secretPath, []byte("elevated-only"), 0o600))

	restricted := &FileLoadContext{
		Options:      &types.Options{},
		TemplatePath: templatePath,
		Catalog:      disk.NewCatalog(templatesDir),
	}
	elevated := &FileLoadContext{
		Options: &types.Options{
			AllowLocalFileAccess: true,
		},
		TemplatePath: templatePath,
		Catalog:      disk.NewCatalog(templatesDir),
	}

	WithFileLoadContext(restricted, func() {
		var elevatedErr error
		WithFileLoadContext(elevated, func() {
			got, err := evalFile(t, fileExpr(secretPath), nil)
			require.NoError(t, err)
			require.Equal(t, "elevated-only", got)
		})

		_, elevatedErr = evalFile(t, fileExpr(secretPath), nil)
		require.Error(t, elevatedErr, "outer sandbox must be restored after nested context returns")
		require.NotContains(t, elevatedErr.Error(), "elevated-only")
	})
}

func TestFileHelperCacheDoesNotCrossContexts(t *testing.T) {
	_, templatesDir, templatePath := setupFileHelperSandbox(t)

	secretDir := t.TempDir()
	secretPath := filepath.Join(secretDir, "secret.txt")
	require.NoError(t, os.WriteFile(secretPath, []byte("must-not-leak"), 0o600))

	elevated := &FileLoadContext{
		Options: &types.Options{
			AllowLocalFileAccess: true,
		},
		TemplatePath: templatePath,
		Catalog:      disk.NewCatalog(templatesDir),
	}
	restricted := &FileLoadContext{
		Options:      &types.Options{},
		TemplatePath: templatePath,
		Catalog:      disk.NewCatalog(templatesDir),
	}

	WithFileLoadContext(elevated, func() {
		got, err := evalFile(t, fileExpr(secretPath), nil)
		require.NoError(t, err)
		require.Equal(t, "must-not-leak", got)
	})

	var got error
	WithFileLoadContext(restricted, func() {
		_, got = evalFile(t, fileExpr(secretPath), nil)
	})
	require.Error(t, got)
	require.NotContains(t, got.Error(), "must-not-leak")
}

func TestFileHelperDeniesSymlinkChainOutsideSandbox(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is not reliable on all Windows runners")
	}

	_, templatesDir, templatePath := setupFileHelperSandbox(t)

	outsideDir := filepath.Join(filepath.Dir(templatesDir), "outside-chain")
	require.NoError(t, os.MkdirAll(outsideDir, 0o755))
	outsideFile := filepath.Join(outsideDir, "secret.txt")
	require.NoError(t, os.WriteFile(outsideFile, []byte("chain-secret"), 0o600))

	midLink := filepath.Join(templatesDir, "mid.link")
	finalLink := filepath.Join(templatesDir, "final.link")
	require.NoError(t, os.Symlink(outsideFile, midLink))
	require.NoError(t, os.Symlink(midLink, finalLink))

	ctx := &FileLoadContext{
		Options:      &types.Options{},
		TemplatePath: templatePath,
		Catalog:      disk.NewCatalog(templatesDir),
	}

	var got error
	WithFileLoadContext(ctx, func() {
		_, got = evalFile(t, fileExpr(finalLink), nil)
	})
	require.Error(t, got)
	require.NotContains(t, got.Error(), "chain-secret")
}

func TestFileHelperEnforcesExactSizeBoundary(t *testing.T) {
	_, templatesDir, templatePath := setupFileHelperSandbox(t)
	templateDir := filepath.Dir(templatePath)

	atLimit := filepath.Join(templateDir, "at-limit.bin")
	overLimit := filepath.Join(templateDir, "over-limit.bin")

	require.NoError(t, os.WriteFile(atLimit, make([]byte, maxFileHelperSize), 0o600))
	require.NoError(t, os.WriteFile(overLimit, make([]byte, maxFileHelperSize+1), 0o600))

	ctx := &FileLoadContext{
		Options:      &types.Options{},
		TemplatePath: templatePath,
		Catalog:      disk.NewCatalog(templatesDir),
	}

	WithFileLoadContext(ctx, func() {
		got, err := evalFile(t, `file("at-limit.bin")`, nil)
		require.NoError(t, err)
		require.Len(t, got, int(maxFileHelperSize))

		_, err = evalFile(t, `file("over-limit.bin")`, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "exceeds maximum size")
	})
}

func TestFileHelperPathArgumentDoesNotExecuteAsExpression(t *testing.T) {
	_, templatesDir, templatePath := setupFileHelperSandbox(t)
	templateDir := filepath.Dir(templatePath)
	require.NoError(t, os.WriteFile(filepath.Join(templateDir, "ok.txt"), []byte("trusted-ok"), 0o600))

	ctx := &FileLoadContext{
		Options:      &types.Options{},
		TemplatePath: templatePath,
		Catalog:      disk.NewCatalog(templatesDir),
	}

	// Path is opaque data; embedded file(...)-looking text must not open ok.txt.
	var (
		got string
		err error
	)
	WithFileLoadContext(ctx, func() {
		got, err = evalFile(t, `file("prefix file(ok.txt) suffix")`, nil)
	})
	require.Error(t, err)
	require.NotEqual(t, "trusted-ok", got)
	require.NotContains(t, err.Error(), "trusted-ok")
}
