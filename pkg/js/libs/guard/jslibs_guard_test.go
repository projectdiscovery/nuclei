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

// forbiddenSelectors is keyed by the package *identifier* used at the call
// site, not the import path. `import "os/exec"` binds the identifier `exec`, so
// a direct `exec.Command(...)` yields the selector key "exec.Command" — the
// import path form "os/exec.Command" would never match.
var forbiddenSelectors = map[string]struct{}{
	"net.Dial":     {},
	"net.Dialer":   {},
	"exec.Command": {},
	"os.Open":      {},
	"os.ReadFile":  {},
	"os.WriteFile": {},
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

		// Inspect every selector expression (pkg.Name), not just call
		// expressions: this catches type references such as net.Dialer and
		// composite literals like net.Dialer{}, not only direct calls.
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			key := pkg.Name + "." + sel.Sel.Name
			if _, blocked := forbiddenSelectors[key]; blocked {
				t.Fatalf("%s uses forbidden selector %s", path, key)
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
