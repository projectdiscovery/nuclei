package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/printer"
	"go/token"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"

	fileutil "github.com/projectdiscovery/utils/file"
	"golang.org/x/tools/imports"
)

var (
	srcFolder   = flag.String("src", "", "source folder")
	dstFolder   = flag.String("dst", "", "destination foldder")
	packageName = flag.String("pkg", "memo", "destination package")
)

func main() {
	flag.Parse()

	_ = fileutil.CreateFolder(*dstFolder)

	err := filepath.WalkDir(*srcFolder, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if ext := filepath.Ext(path); strings.ToLower(ext) != ".go" {
			return nil
		}

		return process(path)
	})
	if err != nil {
		log.Fatal(err)
	}
}

func process(path string) error {
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		return err
	}

	filename := filepath.Base(path)
	dstFile := filepath.Join(*dstFolder, filename)

	var content bytes.Buffer

	content.WriteString(fmt.Sprintf("package %s\n\n", *packageName))

	sourcePackage := node.Name.Name

	ast.Inspect(node, func(n ast.Node) bool {
		switch nn := n.(type) {
		case *ast.FuncDecl:
			if !nn.Name.IsExported() {
				return false
			}
			for _, comment := range nn.Doc.List {
				if comment.Text == "// @memo" {
					var funcs strings.Builder

					hasReturnType := nn.Type.Results != nil && len(nn.Type.Results.List) > 0
					hasParams := nn.Type.Params != nil && len(nn.Type.Params.List) > 0

					var (
						retValuesNames       []string
						retStructFieldsNames []string
						retValuesTypes       []string
						paramNames           []string
					)

					if hasParams {
						for _, param := range nn.Type.Params.List {
							for _, name := range param.Names {
								paramNames = append(paramNames, name.String())
							}
						}
					}

					if hasReturnType {
						for idx, result := range nn.Type.Results.List {
							retValueName := fmt.Sprintf("ret%d%s", idx, nn.Name.Name)
							retValueType := fmt.Sprint(result.Type)
							retValuesNames = append(retValuesNames, retValueName)
							retValuesTypes = append(retValuesTypes, retValueType)
						}
					}
					var retStructName, retStructInstance string
					if hasReturnType && hasParams {
						retStructName = "resStruct" + nn.Name.Name
						retStructInstance = fmt.Sprintf("ret%s", retStructName)
						funcs.WriteString(fmt.Sprintf("type %s struct {", retStructName))
						for idx := range retValuesNames {
							structFieldName := fmt.Sprintf("%s.%s", retStructInstance, retValuesNames[idx])
							retStructFieldsNames = append(retStructFieldsNames, structFieldName)

							funcs.WriteString("\n")
							funcs.WriteString(fmt.Sprintf("%s %s\n", retValuesNames[idx], retValuesTypes[idx]))
						}
						funcs.WriteString("}")
						funcs.WriteString("\n")
					}

					syncOnceName := "once" + nn.Name.Name
					funcs.WriteString("var (\n")
					if !hasParams {
						funcs.WriteString(syncOnceName + " sync.Once")
					}
					if hasReturnType {
						if !hasParams {
							for idx := range retValuesNames {
								funcs.WriteString("\n")
								funcs.WriteString(fmt.Sprintf("%s %s\n", retValuesNames[idx], retValuesTypes[idx]))
							}
						}
					}

					funcs.WriteString("\n)\n")

					var funcSign strings.Builder
					printer.Fprint(&funcSign, fset, nn.Type)
					funcs.WriteString(strings.Replace(funcSign.String(), "func", "func "+nn.Name.Name, 1))
					funcs.WriteString("{")

					if !hasParams {
						returnStatement := strings.Join(retValuesNames, ",")
						funcs.WriteString("\n" + syncOnceName + ".Do(func() {")
						funcs.WriteString("\n")
						if hasReturnType {
							funcs.WriteString(returnStatement + "=")
						}
						funcs.WriteString(sourcePackage + "." + nn.Name.Name + "()")
						funcs.WriteString("})")
						if hasReturnType {
							funcs.WriteString("\nreturn " + returnStatement)
						}
					} else {
						funcs.WriteString(fmt.Sprintf("var %s *%s\n", retStructInstance, retStructName))
						funcs.WriteString("h := hash(")
						funcs.WriteString("\"" + nn.Name.Name + "\", ")
						funcs.WriteString(strings.Join(paramNames, ","))

						funcs.WriteString(")")
						funcs.WriteString("\n")

						funcs.WriteString(`if v, err := cache.GetIFPresent(h); err == nil {
							retresStructTest = v.(*` + retStructName + `)
						}`)

						allStructFields := strings.Join(retStructFieldsNames, ",")

						if hasReturnType {
							funcs.WriteString("\n")
							funcs.WriteString(allStructFields + "=")
						}

						funcs.WriteString(sourcePackage + "." + nn.Name.Name + "(")

						if hasParams {
							var params []string
							for _, param := range nn.Type.Params.List {
								for _, id := range param.Names {
									params = append(params, id.Name)
								}
							}
							funcs.WriteString(strings.Join(params, ", "))
						}
						funcs.WriteString(")")
						funcs.WriteString("\n")
						funcs.WriteString(`cache.Set(h, ` + retStructInstance + `)`)

						funcs.WriteString("\nreturn " + allStructFields)
					}
					funcs.WriteString("}")
					content.WriteString(funcs.String())
					content.WriteString("\n")
				}
			}
			return false
		default:
			return true
		}
	})

	// inject std func
	content.WriteString("\n" + hashFunc)
	content.WriteString("\n" + memoizeCache)

	log.Println(content.String())

	out, err := imports.Process(dstFile, content.Bytes(), nil)
	if err != nil {
		return err
	}

	out, err = format.Source(out)
	if err != nil {
		return err
	}

	return os.WriteFile(dstFile, out, os.ModePerm)
}

var hashFunc = `
func hash(functionName string, args ...any) string {
	var b bytes.Buffer
	b.WriteString(functionName + ":")
	for _, arg := range args {
		b.WriteString(fmt.Sprint(arg))
	}
	h := sha256.Sum256(b.Bytes())
	return hex.EncodeToString(h[:])
}
`

var memoizeCache = `
var cache gcache.Cache[string, interface{}]

func init() {
	cache = gcache.New[string, interface{}](1000).Build()
}`
