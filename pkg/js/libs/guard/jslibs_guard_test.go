package jslibs

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var forbiddenSelectors = map[string]struct{}{
	"net.Dial":        {},
	"net.Dialer":      {},
	"os.Open":         {},
	"os.ReadFile":     {},
	"os.WriteFile":    {},
	"os/exec.Command": {},
}

func TestJSLibsDoNotUseForbiddenSyscalls(t *testing.T) {
	root := ".."
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if strings.Contains(path, string(filepath.Join("guard"))) {
			return nil
		}

		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}

		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			key := pkg.Name + "." + sel.Sel.Name
			if _, blocked := forbiddenSelectors[key]; blocked {
				t.Fatalf("%s uses forbidden call %s", path, key)
			}
			return true
		})
		return nil
	})
	requireNoError(t, err)
}

func requireNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
