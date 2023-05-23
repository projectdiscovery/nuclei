package generator

import (
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"log"
	"os"
	"os/exec"
	"path"
	"strings"
	"text/template"

	_ "embed"

	"github.com/projectdiscovery/nuclei/v2/pkg/js/compiler"
)

//go:embed templates/js_class.tmpl
var jsClassFile string

//go:embed templates/go_class.tmpl
var goClassFile string

//go:embed templates/markdown_class.tmpl
var markdownClassFile string

type TemplateData struct {
	PackageName             string
	PackagePath             string
	PackageFuncs            map[string]string
	PackageInterfaces       map[string]string
	PackageFuncsExtraNoType map[string]PackageFunctionExtra
	PackageFuncsExtra       map[string]PackageFuncExtra
	PackageVars             map[string]string
	PackageVarsValues       map[string]string
	PackageTypes            map[string]string
	PackageTypesExtra       map[string]PackageTypeExtra

	typesPackage *types.Package

	NativeScripts []string
}

type PackageTypeExtra struct {
	Fields map[string]string
}

type PackageFuncExtra struct {
	Items map[string]PackageFunctionExtra
	Doc   string
}

type PackageFunctionExtra struct {
	Args    []string
	Name    string
	Returns []string
	Doc     string
}

func newTemplateData(packagePrefix, pkgName string) *TemplateData {
	return &TemplateData{
		PackageName:             pkgName,
		PackagePath:             packagePrefix + pkgName,
		PackageFuncs:            make(map[string]string),
		PackageFuncsExtraNoType: make(map[string]PackageFunctionExtra),
		PackageFuncsExtra:       make(map[string]PackageFuncExtra),
		PackageVars:             make(map[string]string),
		PackageVarsValues:       make(map[string]string),
		PackageTypes:            make(map[string]string),
		PackageInterfaces:       make(map[string]string),
		PackageTypesExtra:       make(map[string]PackageTypeExtra),
	}
}

// CreateTemplateData creates a TemplateData structure from a directory
// of go source code.
func CreateTemplateData(directory string, packagePrefix string) (*TemplateData, error) {
	fset := token.NewFileSet()

	pkgs, err := parser.ParseDir(fset, directory, nil, parser.ParseComments)
	if err != nil {
		return nil, err
	}
	if len(pkgs) != 1 {
		return nil, fmt.Errorf("expected 1 package, got %d", len(pkgs))
	}

	config := &types.Config{
		Importer: importer.ForCompiler(fset, "source", nil),
	}
	var packageName string
	var files []*ast.File
	for k, v := range pkgs {
		packageName = k
		for _, f := range v.Files {
			files = append(files, f)
		}
		break
	}

	//	ast.Print(fset, files[0])

	pkg, err := config.Check(packageName, fset, files, nil)
	if err != nil {
		log.Fatal(err)
	}

	var pkgMain *ast.Package
	for _, p := range pkgs {
		pkgMain = p
		break
	}

	log.Printf("[create] [discover] Package: %s\n", pkgMain.Name)
	data := newTemplateData(packagePrefix, pkgMain.Name)
	data.typesPackage = pkg
	data.gatherPackageData(pkgMain, data)

	for item, v := range data.PackageFuncsExtra {
		if len(v.Items) == 0 {
			delete(data.PackageFuncsExtra, item)
		}
	}
	return data, nil
}

func (d *TemplateData) WriteJSTemplate(output string, pkgName string) error {
	_ = os.MkdirAll(output, os.ModePerm)

	var err error
	tmpl := template.New("js_class")
	tmpl, err = tmpl.Parse(jsClassFile)
	if err != nil {
		return err
	}

	filename := path.Join(output, fmt.Sprintf("%s.js", pkgName))
	outputFile2, err := os.Create(filename)
	if err != nil {
		return err
	}

	if err := tmpl.Execute(outputFile2, d); err != nil {
		outputFile2.Close()
		return err
	}
	outputFile2.Close()

	cmd := exec.Command("js-beautify", "-r", filename)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	if err := cmd.Run(); err != nil {
		return err
	}
	return nil
}

func (d *TemplateData) InitNativeScripts() {
	compiler := compiler.New()
	runtime := compiler.VM()

	exports := runtime.Get("exports")
	if exports == nil {
		return
	}
	exportsObj := exports.Export()
	if exportsObj == nil {
		return
	}
	for v := range exportsObj.(map[string]interface{}) {
		d.NativeScripts = append(d.NativeScripts, v)
	}
}

func (d *TemplateData) WriteGoTemplate(output string, pkgName string) error {
	_ = os.MkdirAll(output, os.ModePerm)

	var err error
	tmpl := template.New("go_class")
	tmpl = tmpl.Funcs(templateFuncs())
	tmpl, err = tmpl.Parse(goClassFile)
	if err != nil {
		return err
	}

	filename := path.Join(output, fmt.Sprintf("%s.go", pkgName))
	outputFile2, err := os.Create(filename)
	if err != nil {
		return err
	}

	if err := tmpl.Execute(outputFile2, d); err != nil {
		outputFile2.Close()
		return err
	}
	outputFile2.Close()

	cmd := exec.Command("gofmt", "-w", filename)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	if err := cmd.Run(); err != nil {
		return err
	}
	return nil
}

var markdownIndexes = make(map[string]string)

func (d *TemplateData) WriteMarkdownTemplate(output string, pkgName string) error {
	_ = os.MkdirAll(output, os.ModePerm)

	var err error
	tmpl := template.New("markdown_class")
	tmpl = tmpl.Funcs(templateFuncs())
	tmpl, err = tmpl.Parse(markdownClassFile)
	if err != nil {
		return err
	}

	filename := path.Join(output, fmt.Sprintf("%s.md", pkgName))
	outputFile2, err := os.Create(filename)
	if err != nil {
		return err
	}

	markdownIndexes[pkgName] = fmt.Sprintf("[%s](%s.md)", pkgName, pkgName)
	if err := tmpl.Execute(outputFile2, d); err != nil {
		outputFile2.Close()
		return err
	}
	outputFile2.Close()

	return nil
}

func (d *TemplateData) WriteMarkdownIndexTemplate(output string) error {
	_ = os.MkdirAll(output, os.ModePerm)

	filename := path.Join(output, "index.md")
	outputFile2, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer outputFile2.Close()

	outputFile2.WriteString("# Index\n\n")
	for _, v := range markdownIndexes {
		outputFile2.WriteString(fmt.Sprintf("* %s\n", v))
	}
	outputFile2.WriteString("\n\n")

	outputFile2.WriteString("# Scripts\n\n")
	for _, v := range d.NativeScripts {
		outputFile2.WriteString(fmt.Sprintf("* `%s`\n", v))
	}
	return nil
}

func (d *TemplateData) gatherPackageData(pkg *ast.Package, data *TemplateData) {
	ast.Inspect(pkg, func(node ast.Node) bool {
		switch node := node.(type) {
		case *ast.FuncDecl:
			extra := d.collectFuncDecl(node)
			if extra.Name == "" {
				return true
			}
			data.PackageFuncsExtraNoType[node.Name.Name] = extra
			data.PackageFuncs[node.Name.Name] = node.Name.Name
		case *ast.TypeSpec:
			if !node.Name.IsExported() {
				return true
			}
			if node.Type == nil {
				return true
			}
			structDecl, ok := node.Type.(*ast.StructType)
			if !ok {
				return true
			}

			packageTypes := PackageTypeExtra{
				Fields: make(map[string]string),
			}
			for _, field := range structDecl.Fields.List {
				fieldName := field.Names[0].Name

				var fieldTypeValue string
				switch fieldType := field.Type.(type) {
				case *ast.Ident: // Field type is a simple identifier
					fieldTypeValue = fieldType.Name
				case *ast.ArrayType:
					switch fieldType.Elt.(type) {
					case *ast.Ident:
						fieldTypeValue = fmt.Sprintf("[]%s", fieldType.Elt.(*ast.Ident).Name)
					case *ast.StarExpr:
						fieldTypeValue = fmt.Sprintf("[]%s", d.handleStarExpr(fieldType.Elt.(*ast.StarExpr)))
					}
				case *ast.SelectorExpr: // Field type is a qualified identifier
					fieldTypeValue = fmt.Sprintf("%s.%s", fieldType.X, fieldType.Sel)
				}
				packageTypes.Fields[fieldName] = fieldTypeValue
			}
			if len(packageTypes.Fields) == 0 {
				return true
			}
			data.PackageTypesExtra[node.Name.Name] = packageTypes
		case *ast.GenDecl:
			identifyGenDecl(pkg, node, data)
		}
		return true
	})
}

func identifyGenDecl(pkg *ast.Package, decl *ast.GenDecl, data *TemplateData) {
	for _, spec := range decl.Specs {
		switch spec := spec.(type) {
		case *ast.ValueSpec:
			if !spec.Names[0].IsExported() {
				continue
			}
			if spec.Values == nil || len(spec.Values) == 0 {
				continue
			}
			data.PackageVars[spec.Names[0].Name] = spec.Names[0].Name
			data.PackageVarsValues[spec.Names[0].Name] = spec.Values[0].(*ast.BasicLit).Value
		case *ast.TypeSpec:
			if !spec.Name.IsExported() {
				continue
			}
			if spec.Type == nil {
				continue
			}

			switch spec.Type.(type) {
			case *ast.InterfaceType:
				data.PackageInterfaces[spec.Name.Name] = convertCommentsToJavascript(decl.Doc.Text())

			case *ast.StructType:
				data.PackageFuncsExtra[spec.Name.Name] = PackageFuncExtra{
					Items: make(map[string]PackageFunctionExtra),
					Doc:   convertCommentsToJavascript(decl.Doc.Text()),
				}

				// Traverse the AST.
				collectStructFuncsFromAST(pkg, spec, data)
				data.PackageTypes[spec.Name.Name] = spec.Name.Name
			}
		}
	}
}
func collectStructFuncsFromAST(pkg *ast.Package, spec *ast.TypeSpec, data *TemplateData) {
	ast.Inspect(pkg, func(n ast.Node) bool {
		if fn, isFunc := n.(*ast.FuncDecl); isFunc && fn.Name.IsExported() {
			processFunc(fn, spec, data)
		}
		return true
	})
}

func processFunc(fn *ast.FuncDecl, spec *ast.TypeSpec, data *TemplateData) {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return
	}

	if t, ok := fn.Recv.List[0].Type.(*ast.StarExpr); ok {
		if ident, ok := t.X.(*ast.Ident); ok && spec.Name.Name == ident.Name {
			processFunctionDetails(fn, ident, data)
		}
	}
}

func processFunctionDetails(fn *ast.FuncDecl, ident *ast.Ident, data *TemplateData) {
	extra := PackageFunctionExtra{
		Name:    fn.Name.Name,
		Args:    extractArgs(fn),
		Doc:     convertCommentsToJavascript(fn.Doc.Text()),
		Returns: data.extractReturns(fn),
	}
	data.PackageFuncsExtra[ident.Name].Items[fn.Name.Name] = extra
}

func extractArgs(fn *ast.FuncDecl) []string {
	args := make([]string, 0)
	for _, arg := range fn.Type.Params.List {
		for _, name := range arg.Names {
			args = append(args, name.Name)
		}
	}
	return args
}

func (d *TemplateData) extractReturns(fn *ast.FuncDecl) []string {
	returns := make([]string, 0)
	if fn.Type.Results == nil {
		return returns
	}
	for _, ret := range fn.Type.Results.List {
		returnType := d.extractReturnType(ret)
		if returnType != "" {
			returns = append(returns, returnType)
		}
	}
	return returns
}

func (d *TemplateData) extractReturnType(ret *ast.Field) string {
	switch v := ret.Type.(type) {
	case *ast.ArrayType:
		if v, ok := v.Elt.(*ast.Ident); ok {
			return fmt.Sprintf("[]%s", v.Name)
		}
		if v, ok := v.Elt.(*ast.StarExpr); ok {
			return d.handleStarExpr(v)
		}
	case *ast.Ident:
		return v.Name
	case *ast.StarExpr:
		return d.handleStarExpr(v)
	}
	return ""
}

func (d *TemplateData) handleStarExpr(v *ast.StarExpr) string {
	switch vk := v.X.(type) {
	case *ast.Ident:
		return vk.Name
	case *ast.SelectorExpr:
		if vk.X != nil {
			d.collectTypeFromExternal(d.typesPackage, vk.X.(*ast.Ident).Name, vk.Sel.Name)
		}
		return vk.Sel.Name
	}
	return ""
}

func (d *TemplateData) collectTypeFromExternal(pkg *types.Package, pkgName, name string) {
	extra := PackageTypeExtra{
		Fields: make(map[string]string),
	}

	for _, importValue := range pkg.Imports() {
		if importValue.Name() != pkgName {
			continue
		}
		obj := importValue.Scope().Lookup(name)
		if obj == nil || !obj.Exported() {
			continue
		}
		typeName, ok := obj.(*types.TypeName)
		if !ok {
			continue
		}
		underlying, ok := typeName.Type().Underlying().(*types.Struct)
		if !ok {
			continue
		}
		for i := 0; i < underlying.NumFields(); i++ {
			field := underlying.Field(i)
			fieldType := field.Type().String()

			if val, ok := field.Type().Underlying().(*types.Pointer); ok {
				fieldType = field.Name()
				d.collectTypeFromExternal(pkg, pkgName, val.Elem().(*types.Named).Obj().Name())
			}
			if _, ok := field.Type().Underlying().(*types.Struct); ok {
				fieldType = field.Name()
				d.collectTypeFromExternal(pkg, pkgName, field.Name())
			}
			extra.Fields[field.Name()] = fieldType
		}
		if len(extra.Fields) > 0 {
			d.PackageTypesExtra[name] = extra
		}
	}
}

func (d *TemplateData) collectFuncDecl(decl *ast.FuncDecl) (extra PackageFunctionExtra) {
	if decl.Recv != nil {
		return
	}
	if !decl.Name.IsExported() {
		return
	}
	extra.Name = decl.Name.Name
	extra.Doc = convertCommentsToJavascript(decl.Doc.Text())

	for _, arg := range decl.Type.Params.List {
		for _, name := range arg.Names {
			extra.Args = append(extra.Args, name.Name)
		}
	}
	extra.Returns = d.extractReturns(decl)
	return extra
}

// GetModules takes a directory and returns subdirectories as modules
func GetModules(directory string) ([]string, error) {
	dirs, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	var modules []string
	for _, dir := range dirs {
		if dir.IsDir() {
			modules = append(modules, dir.Name())
		}
	}
	return modules, nil
}

func convertCommentsToJavascript(comments string) string {
	suffix := strings.Trim(strings.TrimSuffix(strings.ReplaceAll(comments, "\n", "\n// "), "// "), "\n")
	return fmt.Sprintf("// %s", suffix)
}

func templateFuncs() map[string]interface{} {
	return map[string]interface{}{
		"exist": func(v map[string]string, key string) bool {
			_, exist := v[key]
			return exist
		},
		"toTitle": func(v string) string {
			if len(v) == 0 {
				return v
			}

			return strings.ToUpper(string(v[0])) + v[1:]
		},
		"uncomment": func(v string) string {
			return strings.ReplaceAll(strings.ReplaceAll(v, "// ", " "), "\n", " ")
		},
	}
}
