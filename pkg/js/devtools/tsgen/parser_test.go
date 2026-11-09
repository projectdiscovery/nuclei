package tsgen

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/tools/go/packages"
)

// writeModule writes src as the only package of a new Go module and
// returns the module directory.
func writeModule(t *testing.T, src string) string {
	t.Helper()

	dir := t.TempDir()
	files := map[string]string{
		"go.mod":     "module example.com/tsgentest\n\ngo 1.21\n",
		"example.go": src,
	}

	for name, content := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600))
	}

	return dir
}

func TestNewEntityParser(t *testing.T) {
	const src = `package example

import "strings"

// Upper returns s in upper case.
func Upper(s string) string { return strings.ToUpper(s) }
`

	p, err := NewEntityParser(writeModule(t, src))
	require.NoError(t, err)
	require.NoError(t, p.Parse())

	entities := p.GetEntities()

	names := make([]string, 0, len(entities))
	for _, e := range entities {
		names = append(names, e.Name)
	}

	require.Contains(t, names, "Upper")
}

func TestNewEntityParserPackageErrors(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{name: "syntax error", src: "package example\n\nfunc Broken( {\n\treturn 42\n}\n"},
		{name: "type error", src: "package example\n\nfunc Broken() int { return undefined }\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewEntityParser(writeModule(t, tt.src))
			require.ErrorContains(t, err, "example.go:")
		})
	}
}

func TestLoadImportedPackagesMissing(t *testing.T) {
	const src = `package example; import "example.com/tsgentest/missing"`

	file, err := parser.ParseFile(token.NewFileSet(), "example.go", src, parser.ImportsOnly)
	require.NoError(t, err)
	p := &EntityParser{
		syntax:  []*ast.File{file},
		imports: map[string]*packages.Package{},
	}

	var pkgErr packages.Error

	require.ErrorAs(t, p.loadImportedPackages(), &pkgErr)
	require.Contains(t, pkgErr.Msg, "example.com/tsgentest/missing")
}
