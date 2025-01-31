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
	"strings"

	_ "embed"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/compiler"
)

var (
	//go:embed templates/js_class.tmpl
	jsClassFile string
	//go:embed templates/go_class.tmpl
	goClassFile string
	//go:embed templates/markdown_class.tmpl
	markdownClassFile string
)

// TemplateData contains the parameters for the JS code generator
type TemplateData struct {
	PackageName               string
	PackagePath               string
	HasObjects                bool
	PackageFuncs              map[string]string
	PackageInterfaces         map[string]string
	PackageFuncsExtraNoType   map[string]PackageFunctionExtra
	PackageFuncsExtra         map[string]PackageFuncExtra
	PackageVars               map[string]string
	PackageVarsValues         map[string]string
	PackageTypes              map[string]string
	PackageTypesExtra         map[string]PackageTypeExtra
	PackageDefinedConstructor map[string]struct{}

	typesPackage *types.Package

	// NativeScripts contains the list of native scripts
	// that should be included in the package.
	NativeScripts []string
}

// PackageTypeExtra contains extra information about a type
type PackageTypeExtra struct {
	Fields map[string]string
}

// PackageFuncExtra contains extra information about a function
type PackageFuncExtra struct {
	Items map[string]PackageFunctionExtra
	Doc   string
}

// PackageFunctionExtra contains extra information about a function
type PackageFunctionExtra struct {
	Args    []string
	Name    string
	Returns []string
	Doc     string
}

// newTemplateData creates a new template data structure
func newTemplateData(packagePrefix, pkgName string) *TemplateData {
	return &TemplateData{
		PackageName:               pkgName,
		PackagePath:               packagePrefix + pkgName,
		PackageFuncs:              make(map[string]string),
		PackageFuncsExtraNoType:   make(map[string]PackageFunctionExtra),
		PackageFuncsExtra:         make(map[string]PackageFuncExtra),
		PackageVars:               make(map[string]string),
		PackageVarsValues:         make(map[string]string),
		PackageTypes:              make(map[string]string),
		PackageInterfaces:         make(map[string]string),
		PackageTypesExtra:         make(map[string]PackageTypeExtra),
		PackageDefinedConstructor: make(map[string]struct{}),
	}
}

// GetLibraryModules takes a directory and returns subdirectories as modules
func GetLibraryModules(directory string) ([]string, error) {
	dirs, err := os.ReadDir(directory)
	if err != nil {
		return nil, errors.Wrap(err, "could not read directory")
	}
	var modules []string
	for _, dir := range dirs {
		if dir.IsDir() {
			modules = append(modules, dir.Name())
		}
	}
	return modules, nil
}

// CreateTemplateData creates a TemplateData structure from a directory
// of go source code.
func CreateTemplateData(directory string, packagePrefix string) (*TemplateData, error) {
	fmt.Println(directory)
	fset := token.NewFileSet()

	pkgs, err := parser.ParseDir(fset, directory, nil, parser.ParseComments)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse directory")
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

	pkg, err := config.Check(packageName, fset, files, nil)
	if err != nil {
		return nil, errors.Wrap(err, "could not check package")
	}

	if len(pkgs) == 0 {
		return nil, errors.New("no packages found")
	}

	var pkgName string
	for k := range pkgs {
		pkgName = k
		break
	}

	pkgMain := pkgs[pkgName]

	log.Printf("[create] [discover] Package: %s\n", pkgMain.Name)
	data := newTemplateData(packagePrefix, pkgMain.Name)
	data.typesPackage = pkg
	data.gatherPackageData(pkgMain, data)

	for item, v := range data.PackageFuncsExtra {
		if len(v.Items) == 0 {
			delete(data.PackageFuncsExtra, item)
		}
	}

	// map types with corresponding constructors
	for constructor := range data.PackageDefinedConstructor {
	object:
		for k := range data.PackageTypes {
			if strings.Contains(constructor, k) {
				data.PackageTypes[k] = constructor
				break object
			}
		}
	}
	for k, v := range data.PackageTypes {
		if k == v || v == "" {
			data.HasObjects = true
			data.PackageTypes[k] = ""
		}
	}

	return data, nil
}

// InitNativeScripts initializes the native scripts array
// with all the exported functions from the runtime
func (d *TemplateData) InitNativeScripts() {
	runtime := compiler.InternalGetGeneratorRuntime()

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

// gatherPackageData gathers data about the package
func (d *TemplateData) gatherPackageData(astNode ast.Node, data *TemplateData) {
	ast.Inspect(astNode, func(node ast.Node) bool {
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
			identifyGenDecl(astNode, node, data)
		}
		return true
	})
}

func identifyGenDecl(node ast.Node, decl *ast.GenDecl, data *TemplateData) {
	for _, spec := range decl.Specs {
		switch spec := spec.(type) {
		case *ast.ValueSpec:
			if !spec.Names[0].IsExported() {
				continue
			}
			if len(spec.Values) == 0 {
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
				collectStructFuncsFromAST(node, spec, data)
				data.PackageTypes[spec.Name.Name] = spec.Name.Name
			}
		}
	}
}

func collectStructFuncsFromAST(node ast.Node, spec *ast.TypeSpec, data *TemplateData) {
	ast.Inspect(node, func(n ast.Node) bool {
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
			return fmt.Sprintf("[]%s", d.handleStarExpr(v))
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
	if pkgName == "goja" {
		// no need to attempt to collect types from goja ( this is metadata )
		return
	}
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

	isConstructor := false

	for _, arg := range decl.Type.Params.List {
		p := exprToString(arg.Type)
		if strings.Contains(p, "goja.ConstructorCall") {
			isConstructor = true
		}
		for _, name := range arg.Names {
			extra.Args = append(extra.Args, name.Name)
		}
	}
	if isConstructor {
		d.PackageDefinedConstructor[decl.Name.Name] = struct{}{}
	}

	extra.Returns = d.extractReturns(decl)
	return extra
}

// convertCommentsToJavascript converts comments to javascript comments.
func convertCommentsToJavascript(comments string) string {
	suffix := strings.Trim(strings.TrimSuffix(strings.ReplaceAll(comments, "\n", "\n// "), "// "), "\n")
	return fmt.Sprintf("// %s", suffix)
}

// exprToString converts an expression to a string
func exprToString(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		return exprToString(t.X) + "." + t.Sel.Name
	case *ast.StarExpr:
		return exprToString(t.X)
	case *ast.ArrayType:
		return "[]" + exprToString(t.Elt)
	case *ast.InterfaceType:
		return "interface{}"
	// Add more cases to handle other types
	default:
		return fmt.Sprintf("%T", expr)
	}
}
