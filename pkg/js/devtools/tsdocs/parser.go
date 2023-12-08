package tsdocs

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"

	"github.com/projectdiscovery/gologger"
	sliceutil "github.com/projectdiscovery/utils/slice"
	"golang.org/x/tools/go/packages"
)

// EntityParser is responsible for parsing a go file and generating
// corresponding typescript entities.
type EntityParser struct {
	root        *ast.File
	structTypes map[string]Entity
	imports     map[string]*packages.Package
	newObjects  map[string]*Entity // new objects to create from external packages
	entities    []Entity
}

// NewEntityParser creates a new EntityParser
func NewEntityParser(filePath string) (*EntityParser, error) {
	fset := token.NewFileSet()
	// Parse the file given by filePath
	node, err := parser.ParseFile(fset, filePath, nil, parser.ParseComments)
	if err != nil {
		return nil, err
	}
	return &EntityParser{
		root:        node,
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
	// extract all struct types from the AST
	p.extractStructTypes()
	// load all imported packages
	if err := p.loadImportedPackages(); err != nil {
		return err
	}

	// Traverse the AST and find all relevant declarations
	ast.Inspect(p.root, func(n ast.Node) bool {
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
				p.structTypes[typeSpec.Name.Name] = entity
			} else {
				p.structTypes[typeSpec.Name.Name] = entity
			}
			return false
		}
		// Continue traversing the AST
		return true
	})

	// add all struct types to the list of global entities
	for k, v := range p.structTypes {
		if v.Type == "class" && len(v.Class.Methods) > 0 {
			p.entities = append(p.entities, v)
		} else if v.Type == "class" && len(v.Class.Methods) == 0 {
			entity := Entity{
				Name:        k,
				Type:        "interface",
				Description: strings.ReplaceAll(v.Description, "Class", "interface"),
				Object: Interface{
					Properties: v.Class.Properties,
				},
			}
			p.entities = append(p.entities, entity)
		}
	}

	// handle external structs
	for k := range p.newObjects {
		if err := p.scrapeAndCreate(k); err != nil {
			return err
		}
	}

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
	// fix/adjust return statement
	if entity.Function.Returns == "void" {
		entity.Function.ReturnStmt = "return;"
	} else if strings.Contains(entity.Function.Returns, "null") {
		entity.Function.ReturnStmt = "return null;"
	}
	return entity, nil
}

// extractReturnType extracts the return type from the given function
func (p *EntityParser) extractReturnType(fn *ast.FuncDecl) (out string) {
	var returns []string
	if fn.Type.Results != nil && len(fn.Type.Results.List) > 0 {
		for _, result := range fn.Type.Results.List {
			tmp := exprToString(result.Type)
			if strings.Contains(tmp, ".") {
				tmp = p.handleExternalStruct(tmp)
			}
			returns = append(returns, tmp)
		}
	}
	if len(returns) == 1 {
		val := returns[0]
		val = strings.TrimPrefix(val, "*")
		if val == "error" {
			out = "void"
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

// extractParameters extracts all parameters from the given function
func (p *EntityParser) extractParameters(fn *ast.FuncDecl) []Parameter {
	var parameters []Parameter
	for _, param := range fn.Type.Params.List {
		// get the parameter name
		name := param.Names[0].Name
		// get the parameter type
		typ := exprToString(param.Type)
		// add the parameter to the list of parameters
		parameters = append(parameters, Parameter{
			Name: name,
			Type: typ,
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
	ast.Inspect(p.root, func(n ast.Node) bool {
		// Check if the node is a type specification (which includes structs)
		typeSpec, ok := n.(*ast.TypeSpec)
		if ok {
			// Check if the type specification is a struct type
			_, ok := typeSpec.Type.(*ast.StructType)
			if ok {
				// Add the struct name to the list of struct names
				p.structTypes[typeSpec.Name.Name] = Entity{}
			}
		}
		// Continue traversing the AST
		return true
	})
}

// loadImportedPackages loads all imported packages
func (p *EntityParser) loadImportedPackages() error {
	// get all import statements
	imports := p.root.Imports
	// iterate over all imports
	for _, imp := range imports {
		// get the package path
		path := imp.Path.Value
		// remove the quotes from the path
		path = path[1 : len(path)-1]
		// load the package
		pkg, err := loadPackage(path)
		if err != nil {
			return err
		}
		// add the package to the map
		p.imports[path[strings.LastIndex(path, "/")+1:]] = pkg
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
