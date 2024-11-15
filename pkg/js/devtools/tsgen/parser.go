package tsgen

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"strings"

	"github.com/projectdiscovery/gologger"
	sliceutil "github.com/projectdiscovery/utils/slice"
	"golang.org/x/tools/go/packages"
)

// EntityParser is responsible for parsing a go file and generating
// corresponding typescript entities.
type EntityParser struct {
	syntax      []*ast.File
	structTypes map[string]Entity
	imports     map[string]*packages.Package
	newObjects  map[string]*Entity // new objects to create from external packages
	vars        []Entity
	entities    []Entity
}

// NewEntityParser creates a new EntityParser
func NewEntityParser(dir string) (*EntityParser, error) {

	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedImports |
			packages.NeedTypes | packages.NeedSyntax | packages.NeedTypes |
			packages.NeedModule | packages.NeedTypesInfo,
		Tests: false,
		Dir:   dir,
		ParseFile: func(fset *token.FileSet, filename string, src []byte) (*ast.File, error) {
			return parser.ParseFile(fset, filename, src, parser.ParseComments)
		},
	}
	pkgs, err := packages.Load(cfg, ".")
	if err != nil {
		return nil, err
	}
	if len(pkgs) == 0 {
		return nil, errors.New("no packages found")
	}
	pkg := pkgs[0]

	return &EntityParser{
		syntax:      pkg.Syntax,
		structTypes: map[string]Entity{},
		imports:     map[string]*packages.Package{},
		newObjects:  map[string]*Entity{},
	}, nil
}

func (p *EntityParser) GetEntities() []Entity {
	return p.entities
}

// Parse parses the given file and generates corresponding typescript entities
func (p *EntityParser) Parse() error {
	p.extractVarsNConstants()
	// extract all struct types from the AST
	p.extractStructTypes()
	// load all imported packages
	if err := p.loadImportedPackages(); err != nil {
		return err
	}

	for _, file := range p.syntax {
		// Traverse the AST and find all relevant declarations
		ast.Inspect(file, func(n ast.Node) bool {
			// look for funtions and methods
			// and generate entities for them
			fn, ok := n.(*ast.FuncDecl)
			if ok {
				if !isExported(fn.Name.Name) {
					return false
				}
				entity, err := p.extractFunctionFromNode(fn)
				if err != nil {
					gologger.Error().Msgf("Could not extract function %s: %s\n", fn.Name.Name, err)
					return false
				}

				if entity.IsConstructor {
					// add this to the list of entities
					p.entities = append(p.entities, entity)
					return false
				}

				// check if function has a receiver
				if fn.Recv != nil {
					// get the name of the receiver
					receiverName := exprToString(fn.Recv.List[0].Type)
					// check if the receiver is a struct
					if _, ok := p.structTypes[receiverName]; ok {
						// add the method to the class
						method := Method{
							Name:        entity.Name,
							Description: strings.ReplaceAll(entity.Description, "Function", "Method"),
							Parameters:  entity.Function.Parameters,
							Returns:     entity.Function.Returns,
							CanFail:     entity.Function.CanFail,
							ReturnStmt:  entity.Function.ReturnStmt,
						}

						// add this method to corresponding class
						allMethods := p.structTypes[receiverName].Class.Methods
						if allMethods == nil {
							allMethods = []Method{}
						}
						entity = p.structTypes[receiverName]
						entity.Class.Methods = append(allMethods, method)
						p.structTypes[receiverName] = entity
						return false
					}
				}
				// add the function to the list of global entities
				p.entities = append(p.entities, entity)
				return false
			}

			return true
		})
	}

	for _, file := range p.syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			// logic here to extract all fields and methods from a struct
			// and add them to the entities slice
			// TODO: we only support structs and not type aliases
			typeSpec, ok := n.(*ast.TypeSpec)
			if ok {
				if !isExported(typeSpec.Name.Name) {
					return false
				}
				structType, ok := typeSpec.Type.(*ast.StructType)
				if !ok {
					// This is not a struct, so continue traversing the AST
					return false
				}
				entity := Entity{
					Name:        typeSpec.Name.Name,
					Type:        "class",
					Description: Ternary(strings.TrimSpace(typeSpec.Doc.Text()) != "", typeSpec.Doc.Text(), typeSpec.Name.Name+" Class"),
					Class: Class{
						Properties: p.extractClassProperties(structType),
					},
				}
				// map struct name to entity and create a new entity if doesn't exist
				if _, ok := p.structTypes[typeSpec.Name.Name]; ok {
					entity.Class.Methods = p.structTypes[typeSpec.Name.Name].Class.Methods
					entity.Description = p.structTypes[typeSpec.Name.Name].Description
					p.structTypes[typeSpec.Name.Name] = entity
				} else {
					p.structTypes[typeSpec.Name.Name] = entity
				}
				return false
			}
			// Continue traversing the AST
			return true
		})
	}

	// add all struct types to the list of global entities
	for k, v := range p.structTypes {
		if v.Type == "class" && len(v.Class.Methods) > 0 {
			p.entities = append(p.entities, v)
		} else if v.Type == "class" && len(v.Class.Methods) == 0 {
			if k == "Object" {
				continue
			}
			entity := Entity{
				Name:        k,
				Type:        "interface",
				Description: strings.TrimSpace(strings.ReplaceAll(v.Description, "Class", "interface")),
				Object: Interface{
					Properties: v.Class.Properties,
				},
			}
			p.entities = append(p.entities, entity)
		}
	}

	// handle external structs
	for k := range p.newObjects {
		// if k == "Object" {
		// 	continue
		// }
		if err := p.scrapeAndCreate(k); err != nil {
			return fmt.Errorf("could not scrape and create new object: %s", err)
		}
	}

	interfaceList := map[string]struct{}{}
	for _, v := range p.entities {
		if v.Type == "interface" {
			interfaceList[v.Name] = struct{}{}
		}
	}

	// handle method return types
	for index, v := range p.entities {
		if len(v.Class.Methods) > 0 {
			for i, method := range v.Class.Methods {
				if !strings.Contains(method.Returns, "null") {
					x := strings.TrimSpace(method.Returns)
					if _, ok := interfaceList[x]; ok {
						// non nullable interface return type detected
						method.Returns = x + " | null"
						method.ReturnStmt = "return null;"
						p.entities[index].Class.Methods[i] = method
					}
				}
			}
		}
	}

	// handle constructors
	for _, v := range p.entities {
		if v.IsConstructor {

			// correlate it with the class
		foundStruct:
			for i, class := range p.entities {
				if class.Type != "class" {
					continue foundStruct
				}
				if strings.Contains(v.Name, class.Name) {
					// add constructor to the class
					p.entities[i].Class.Constructor = v.Function
					break foundStruct
				}
			}
		}
	}

	filtered := []Entity{}
	for _, v := range p.entities {
		if !v.IsConstructor {
			filtered = append(filtered, v)
		}
	}

	// add all vars and constants
	filtered = append(filtered, p.vars...)

	p.entities = filtered
	return nil
}

// extractPropertiesFromStruct extracts all properties from the given struct
func (p *EntityParser) extractClassProperties(node *ast.StructType) []Property {
	var properties []Property

	for _, field := range node.Fields.List {
		// Skip unexported fields
		if len(field.Names) > 0 && !field.Names[0].IsExported() {
			continue
		}

		// Get the type of the field as a string
		typeString := exprToString(field.Type)

		// If the field is anonymous (embedded), use the type name as the field name
		if len(field.Names) == 0 {
			if ident, ok := field.Type.(*ast.Ident); ok {
				properties = append(properties, Property{
					Name:        ident.Name,
					Type:        typeString,
					Description: field.Doc.Text(),
				})
			}
			continue
		}

		// Iterate through all names (for multiple names in a single declaration)
		for _, fieldName := range field.Names {
			// Only consider exported fields
			if fieldName.IsExported() {
				property := Property{
					Name:        fieldName.Name,
					Type:        typeString,
					Description: field.Doc.Text(),
				}
				if strings.Contains(property.Type, ".") {
					// external struct found
					property.Type = p.handleExternalStruct(property.Type)
				}
				properties = append(properties, property)
			}
		}
	}
	return properties
}

var (
	constructorRe         = `(constructor\([^)]*\))`
	constructorReCompiled = regexp.MustCompile(constructorRe)
)

// extractFunctionFromNode extracts a function from the given AST node
func (p *EntityParser) extractFunctionFromNode(fn *ast.FuncDecl) (Entity, error) {
	entity := Entity{
		Name:        fn.Name.Name,
		Type:        "function",
		Description: Ternary(strings.TrimSpace(fn.Doc.Text()) != "", fn.Doc.Text(), fn.Name.Name+" Function"),
		Function: Function{
			Parameters: p.extractParameters(fn),
			Returns:    p.extractReturnType(fn),
			CanFail:    checkCanFail(fn),
		},
	}
	// check if it is a constructor
	if strings.Contains(entity.Function.Returns, "Object") && len(entity.Function.Parameters) == 2 {
		// this is a constructor defined that accepts something as input
		// get constructor signature from comments
		constructorSig := constructorReCompiled.FindString(entity.Description)
		entity.IsConstructor = true
		entity.Function = updateFuncWithConstructorSig(constructorSig, entity.Function)
		return entity, nil
	}

	// fix/adjust return statement
	if entity.Function.Returns == "void" {
		entity.Function.ReturnStmt = "return;"
	} else if strings.Contains(entity.Function.Returns, "null") {
		entity.Function.ReturnStmt = "return null;"
	} else if fn.Recv != nil && exprToString(fn.Recv.List[0].Type) == entity.Function.Returns {
		entity.Function.ReturnStmt = "return this;"
	} else {
		entity.Function.ReturnStmt = "return " + TsDefaultValue(entity.Function.Returns) + ";"
	}
	return entity, nil
}

// extractReturnType extracts the return type from the given function
func (p *EntityParser) extractReturnType(fn *ast.FuncDecl) (out string) {
	defer func() {
		if out == "" {
			out = "void"
		}
		if strings.Contains(out, "interface{}") {
			out = strings.ReplaceAll(out, "interface{}", "any")
		}
	}()
	var returns []string
	if fn.Type.Results != nil && len(fn.Type.Results.List) > 0 {
		for _, result := range fn.Type.Results.List {
			tmp := exprToString(result.Type)
			if strings.Contains(tmp, ".") && !strings.HasPrefix(tmp, "goja.") {
				tmp = p.handleExternalStruct(tmp) + " | null" // external object interfaces can always return null
			}
			returns = append(returns, tmp)
		}
	}
	if len(returns) == 1 {
		val := returns[0]
		val = strings.TrimPrefix(val, "*")
		if val == "error" {
			out = "void"
		} else {
			out = val
		}
		return
	}
	if len(returns) > 1 {
		// in goja we stick 2 only 2 values with one being error
		for _, val := range returns {
			val = strings.TrimPrefix(val, "*")
			if val != "error" {
				out = val
				break
			}
		}
		if sliceutil.Contains(returns, "error") {
			// add | null to the return type
			out = out + " | null"
			return
		}
	}
	return "void"
}

// example: Map[string][]string -> Record<string, string[]>
func convertMaptoRecord(input string) (out string) {
	var key, value string
	input = strings.TrimPrefix(input, "Map[")
	key = input[:strings.Index(input, "]")]
	value = input[strings.Index(input, "]")+1:]
	return "Record<" + toTsTypes(key) + ", " + toTsTypes(value) + ">"
}

// extractParameters extracts all parameters from the given function
func (p *EntityParser) extractParameters(fn *ast.FuncDecl) []Parameter {
	var parameters []Parameter
	for _, param := range fn.Type.Params.List {
		// get the parameter name
		name := param.Names[0].Name
		// get the parameter type
		typ := exprToString(param.Type)
		if strings.Contains(typ, ".") {
			// replace with any
			// we do not support or encourage passing external structs as parameters
			typ = "any"
		}
		// add the parameter to the list of parameters
		parameters = append(parameters, Parameter{
			Name: name,
			Type: toTsTypes(typ),
		})
	}
	return parameters
}

// typeName is in format ssh.ClientConfig
// it first fetches all fields from the struct and creates a new object
// with that name and returns name of that object as type
func (p *EntityParser) handleExternalStruct(typeName string) string {
	baseType := typeName[strings.LastIndex(typeName, ".")+1:]
	p.newObjects[typeName] = &Entity{
		Name:        baseType,
		Type:        "interface",
		Description: baseType + " Object",
	}
	// @tarunKoyalwar: scrape and create new object
	// pkg := pkgMap[strings.Split(tmp, ".")[0]]
	// if pkg == nil {
	// 	for k := range pkgMap {
	// 		fmt.Println(k)
	// 	}
	// 	panic("package not found")
	// }
	// props, err := extractFieldsFromType(pkg, tmp[strings.LastIndex(tmp, ".")+1:])
	// if err != nil {
	// 	panic(err)
	// }
	// // newObject := Entity{
	// // 	Name: tmp[strings.LastIndex(tmp, ".")+1:],
	// // 	Type: "interface",
	// // 	Object: Object{
	// // 		Properties: props,
	// // 	},
	// // }
	// fmt.Println(props)
	return baseType
}

// extractStructTypes extracts all struct types from the AST
func (p *EntityParser) extractStructTypes() {
	for _, file := range p.syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			// Check if the node is a type specification (which includes structs)
			typeSpec, ok := n.(*ast.TypeSpec)
			if ok {
				// Check if the type specification is a struct type
				_, ok := typeSpec.Type.(*ast.StructType)
				if ok {
					// Add the struct name to the list of struct names
					p.structTypes[typeSpec.Name.Name] = Entity{
						Name:        typeSpec.Name.Name,
						Description: typeSpec.Doc.Text(),
					}
				}
			}
			// Continue traversing the AST
			return true
		})
	}

}

// extraGlobalConstant and vars
func (p *EntityParser) extractVarsNConstants() {
	p.vars = []Entity{}
	for _, file := range p.syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			// Check if the node is a type specification (which includes structs)
			gen, ok := n.(*ast.GenDecl)
			if !ok {
				return true
			}
			for _, v := range gen.Specs {
				switch spec := v.(type) {
				case *ast.ValueSpec:
					if !spec.Names[0].IsExported() {
						continue
					}
					if len(spec.Values) == 0 {
						continue
					}
					// get comments or description
					p.vars = append(p.vars, Entity{
						Name:        spec.Names[0].Name,
						Type:        "const",
						Description: strings.TrimSpace(spec.Comment.Text()),
						Value:       spec.Values[0].(*ast.BasicLit).Value,
					})
				}
			}
			// Continue traversing the AST
			return true
		})
	}
}

// loadImportedPackages loads all imported packages
func (p *EntityParser) loadImportedPackages() error {
	// get all import statements
	// iterate over all imports
	for _, file := range p.syntax {
		for _, imp := range file.Imports {
			// get the package path
			path := imp.Path.Value
			// remove the quotes from the path
			path = path[1 : len(path)-1]
			// load the package
			pkg, err := loadPackage(path)
			if err != nil {
				return err
			}
			importName := path[strings.LastIndex(path, "/")+1:]
			if imp.Name != nil {
				importName = imp.Name.Name
			} else {
				if !strings.HasSuffix(imp.Path.Value, pkg.Types.Name()+`"`) {
					importName = pkg.Types.Name()
				}
			}
			// add the package to the map
			if _, ok := p.imports[importName]; !ok {
				p.imports[importName] = pkg
			}
		}
	}
	return nil
}

// Load the package containing the type definition
// TODO: we don't support named imports yet
func loadPackage(pkgPath string) (*packages.Package, error) {
	cfg := &packages.Config{Mode: packages.NeedTypes | packages.NeedSyntax | packages.NeedTypesInfo}
	pkgs, err := packages.Load(cfg, pkgPath)
	if err != nil {
		return nil, err
	}
	if len(pkgs) == 0 {
		return nil, errors.New("no packages found")
	}
	return pkgs[0], nil
}

// exprToString converts an expression to a string
func updateFuncWithConstructorSig(sig string, f Function) Function {
	sig = strings.TrimSpace(sig)
	f.Parameters = []Parameter{}
	f.CanFail = true
	f.ReturnStmt = ""
	f.Returns = ""
	if sig == "" {
		return f
	}
	// example: constructor(public domain: string, public controller?: string)
	// remove constructor( and )
	sig = strings.TrimPrefix(sig, "constructor(")
	sig = strings.TrimSuffix(sig, ")")
	// split by comma
	args := strings.Split(sig, ",")
	for _, arg := range args {
		arg = strings.TrimSpace(arg)
		// check if it is optional
		typeData := strings.Split(arg, ":")
		if len(typeData) != 2 {
			panic("invalid constructor signature")
		}
		f.Parameters = append(f.Parameters, Parameter{
			Name: strings.TrimSpace(typeData[0]),
			Type: strings.TrimSpace(typeData[1]),
		})
	}
	return f
}
