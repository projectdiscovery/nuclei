package tsgen

import (
	"fmt"
	"go/ast"
	"strings"
)

// isExported checks if the given name is exported
func isExported(name string) bool {
	return ast.IsExported(name)
}

// exprToString converts an expression to a string
func exprToString(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return toTsTypes(t.Name)
	case *ast.SelectorExpr:
		return exprToString(t.X) + "." + t.Sel.Name
	case *ast.StarExpr:
		return exprToString(t.X)
	case *ast.ArrayType:
		return toTsTypes("[]" + exprToString(t.Elt))
	case *ast.InterfaceType:
		return "interface{}"
	case *ast.MapType:
		return "Record<" + toTsTypes(exprToString(t.Key)) + ", " + toTsTypes(exprToString(t.Value)) + ">"
	// Add more cases to handle other types
	default:
		return fmt.Sprintf("%T", expr)
	}
}

// toTsTypes converts Go types to TypeScript types
func toTsTypes(t string) string {
	if strings.Contains(t, "interface{}") {
		return "any"
	}
	if strings.HasPrefix(t, "map[") {
		return convertMaptoRecord(t)
	}
	switch t {
	case "string":
		return "string"
	case "int", "int8", "int16", "int32", "int64", "uint", "uint8", "uint16", "uint32", "uint64":
		return "number"
	case "float32", "float64":
		return "number"
	case "bool":
		return "boolean"
	case "[]byte":
		return "Uint8Array"
	case "interface{}":
		return "any"
	case "time.Duration":
		return "number"
	case "time.Time":
		return "Date"
	default:
		if strings.HasPrefix(t, "[]") {
			return toTsTypes(strings.TrimPrefix(t, "[]")) + "[]"
		}
		return t
	}
}

func TsDefaultValue(t string) string {
	switch t {
	case "string":
		return `""`
	case "number":
		return `0`
	case "boolean":
		return `false`
	case "Uint8Array":
		return `new Uint8Array(8)`
	case "any":
		return `undefined`
	case "interface{}":
		return `undefined`
	default:
		if strings.Contains(t, "[]") {
			return `[]`
		}
		return "new " + t + "()"
	}
}

// Ternary is a ternary operator for strings
func Ternary(condition bool, trueVal, falseVal string) string {
	if condition {
		return trueVal
	}
	return falseVal
}

// checkCanFail checks if a function can fail
func checkCanFail(fn *ast.FuncDecl) bool {
	if fn.Type.Results != nil {
		for _, result := range fn.Type.Results.List {
			// Check if any of the return types is an error
			if ident, ok := result.Type.(*ast.Ident); ok && ident.Name == "error" {
				return true
			}
		}
	}
	return false
}
