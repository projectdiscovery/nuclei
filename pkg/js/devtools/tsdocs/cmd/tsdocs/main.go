package main

import (
	_ "embed"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"text/template"

	"github.com/projectdiscovery/nuclei/v3/pkg/js/devtools/tsdocs"
	sliceutil "github.com/projectdiscovery/utils/slice"
	"golang.org/x/tools/go/packages"
)

// Define your template
//
//go:embed tsmodule.go.tmpl
var tsTemplate string

// Define a struct to hold information about your TypeScript entities
type Entity struct {
	Name        string
	Type        string // "class", "function", or "object"
	Description string
	Example     string   // this will be part of description with @example jsdoc tag
	Class       Class    // if Type == "class"
	Function    Function // if Type == "function"
	Object      Object   // if Type == "object"
}

// Class represents a TypeScript class data structure
type Class struct {
	Properties []Property
	Methods    []Method
}

// Function represents a TypeScript function data structure
// If CanFail is true, the function returns a Result<T, E> type
// So modify the function signature to return a Result<T, E> type in this case
type Function struct {
	Parameters []Parameter
	Returns    string
	CanFail    bool
	ReturnStmt string
}

type Object struct {
	Properties []Property
}

// Method represents a TypeScript method data structure
// If CanFail is true, the method returns a Result<T, E> type
// So modify the method signature to return a Result<T, E> type in this case
type Method struct {
	Name        string
	Description string
	Parameters  []Parameter
	Returns     string
	CanFail     bool
	ReturnStmt  string
}

type Property struct {
	Name        string
	Type        string
	Description string
}

type Parameter struct {
	Name string
	Type string
}

func main() {
	// Create an instance of the template
	tmpl := template.New("ts")
	tmpl = tmpl.Funcs(template.FuncMap{
		"splitLines": func(s string) []string {
			tmp := strings.Split(s, "\n")
			filtered := []string{}
			for _, line := range tmp {
				if strings.TrimSpace(line) != "" {
					filtered = append(filtered, line)
				}
			}
			return filtered
		},
	})
	var err error
	tmpl, err = tmpl.Parse(tsTemplate)
	if err != nil {
		panic(err)
	}

	// // Example data with function, class, and object entities
	// entities := []Entity{
	// 	{
	// 		Type:        "function",
	// 		Name:        "exampleFunction",
	// 		Description: "This is an example function",
	// 		Function: Function{
	// 			Parameters: []Parameter{{Name: "arg", Type: "any"}, {Name: "arg2", Type: "number"}},
	// 			Returns:    "string",
	// 			CanFail:    true,
	// 		},
	// 	},
	// 	{
	// 		Type:        "class",
	// 		Name:        "ExampleClass",
	// 		Description: "This is an example class",
	// 		Class: Class{
	// 			Properties: []Property{
	// 				{Name: "property1", Type: "string", Description: "This is a string property"},
	// 				{Name: "property2", Type: "number", Description: "This is a number property"},
	// 			},
	// 			Methods: []Method{
	// 				{
	// 					Name:        "method1",
	// 					Description: "This is an example method",
	// 					Parameters:  []Parameter{{Name: "arg", Type: "any"}},
	// 					Returns:     "string",
	// 					CanFail:     true,
	// 				},
	// 			},
	// 		},
	// 	},
	// 	{
	// 		Type:        "object",
	// 		Name:        "exampleObject",
	// 		Description: "This is an example object",
	// 		Object: Object{
	// 			Properties: []Property{
	// 				{Name: "key1", Type: "string", Description: "This is a key-value pair"},
	// 				{Name: "key2", Type: "boolean", Description: "This is another key-value pair"},
	// 			},
	// 		},
	// 	},
	// }

	// // Execute the template with the data and write to stdout (or to a file)
	// err = tmpl.Execute(os.Stdout, entities)
	// if err != nil {
	// 	panic(err)
	// }

	ep, err := tsdocs.NewEntityParser("../../../../libs/ssh/ssh.go")
	if err != nil {
		panic(err)
	}
	if err := ep.Parse(); err != nil {
		panic(err)
	}
	err = tmpl.Execute(os.Stdout, ep.GetEntities())
	if err != nil {
		panic(err)
	}

}

func GenerateEntitiesFromFile(filePath string) ([]Entity, error) {
	fset := token.NewFileSet() // positions are relative to fset

	// Parse the file given by filePath
	node, err := parser.ParseFile(fset, filePath, nil, parser.ParseComments)
	if err != nil {
		return nil, err
	}

	var entities []Entity

	structTypes := extractStructNames(node)

	pkgs := pkgMap(node)

	// Traverse the AST and find all relevant declarations
	ast.Inspect(node, func(n ast.Node) bool {
		// look for funtions and methods
		// and generate entities for them
		fn, ok := n.(*ast.FuncDecl)
		if ok {
			if !isExported(fn.Name.Name) {
				return false
			}
			entity := Entity{
				Name:        fn.Name.Name,
				Type:        "function",
				Description: Ternary(strings.TrimSpace(fn.Doc.Text()) != "", fn.Doc.Text(), fn.Name.Name+" Function"),
				Function: Function{
					Parameters: extractParameters(fn),
					Returns:    extractReturnType(fn, pkgs),
					CanFail:    checkCanFail(fn),
				},
			}
			if entity.Function.Returns == "void" {
				entity.Function.ReturnStmt = "return;"
			} else if strings.Contains(entity.Function.Returns, "null") {
				entity.Function.ReturnStmt = "return null;"
			}
			// check if function has a receiver
			if fn.Recv != nil {
				// get the name of the receiver
				receiverName := exprToString(fn.Recv.List[0].Type)
				// check if the receiver is a struct
				if _, ok := structTypes[receiverName]; ok {
					// add the method to the class
					method := Method{
						Name:        fn.Name.Name,
						Description: Ternary(strings.TrimSpace(fn.Doc.Text()) != "", fn.Doc.Text(), fn.Name.Name+" Method"),
						Parameters:  extractParameters(fn),
						Returns:     extractReturnType(fn, pkgs),
						CanFail:     checkCanFail(fn),
					}
					if method.Returns == "void" {
						method.ReturnStmt = "return;"
					} else if strings.Contains(method.Returns, "null") {
						method.ReturnStmt = "return null;"
					}
					allMethods := structTypes[receiverName].Class.Methods
					if allMethods == nil {
						allMethods = []Method{}
					}
					entity = structTypes[receiverName]
					entity.Class.Methods = append(allMethods, method)
					structTypes[receiverName] = entity
					return false
				}
			}
			entities = append(entities, entity)
			return false
		}

		// logic here to extract all fields and methods from a struct
		// and add them to the entities slice
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
					Properties: generatePropertiesFromStruct(structType, pkgs),
				},
			}
			if _, ok := structTypes[typeSpec.Name.Name]; ok {
				entity.Class.Methods = structTypes[typeSpec.Name.Name].Class.Methods
				structTypes[typeSpec.Name.Name] = entity
			} else {
				structTypes[typeSpec.Name.Name] = entity
			}
			return false
		}

		// Continue traversing the AST
		return true
	})

	for k, v := range structTypes {
		if v.Type == "class" && len(v.Class.Methods) > 0 {
			entities = append(entities, v)
		} else if v.Type == "class" && len(v.Class.Methods) == 0 {
			entity := Entity{
				Name:        k,
				Type:        "object",
				Description: strings.ReplaceAll(v.Description, "Class", "Object"),
				Object: Object{
					Properties: v.Class.Properties,
				},
			}
			entities = append(entities, entity)
		}
	}

	return entities, nil
}

func isExported(name string) bool {
	return ast.IsExported(name)
}

func extractStructNames(node *ast.File) map[string]Entity {
	structs := map[string]Entity{}

	ast.Inspect(node, func(n ast.Node) bool {
		// Check if the node is a type specification (which includes structs)
		typeSpec, ok := n.(*ast.TypeSpec)
		if ok {
			// Check if the type specification is a struct type
			_, ok := typeSpec.Type.(*ast.StructType)
			if ok {
				// Add the struct name to the list of struct names
				structs[typeSpec.Name.Name] = Entity{}
			}
		}
		// Continue traversing the AST
		return true
	})

	return structs
}

func generatePropertiesFromStruct(node *ast.StructType, pkgMap map[string]*packages.Package) []Property {
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
				properties = append(properties, property)
				if strings.Contains(property.Type, ".") {
					pkg := pkgMap[strings.Split(property.Type, ".")[0]]
					if pkg == nil {
						for k := range pkgMap {
							fmt.Println(k)
						}
						panic("package not found")
					}
					props, err := extractFieldsFromType(pkg, property.Type[strings.LastIndex(property.Type, ".")+1:])
					if err != nil {
						panic(err)
					}
					newObject := Entity{
						Name: property.Type[strings.LastIndex(property.Type, ".")+1:],
						Type: "object",
						Object: Object{
							Properties: props,
						},
					}
					fmt.Println(newObject)
					property.Type = "any" // external struct
				}
			}
		}
	}

	return properties
}

func extractParameters(fn *ast.FuncDecl) []Parameter {
	var params []Parameter
	for _, field := range fn.Type.Params.List {
		paramType := exprToString(field.Type)
		for _, paramName := range field.Names {
			params = append(params, Parameter{Name: paramName.Name, Type: paramType})
		}
	}
	return params
}

func extractReturnType(fn *ast.FuncDecl, pkgMap map[string]*packages.Package) (out string) {
	var returns []string
	if fn.Type.Results != nil && len(fn.Type.Results.List) > 0 {
		for _, result := range fn.Type.Results.List {
			tmp := exprToString(result.Type)
			if strings.Contains(tmp, ".") {
				pkg := pkgMap[strings.Split(tmp, ".")[0]]
				if pkg == nil {
					for k := range pkgMap {
						fmt.Println(k)
					}
					panic("package not found")
				}
				props, err := extractFieldsFromType(pkg, tmp[strings.LastIndex(tmp, ".")+1:])
				if err != nil {
					panic(err)
				}
				// newObject := Entity{
				// 	Name: tmp[strings.LastIndex(tmp, ".")+1:],
				// 	Type: "object",
				// 	Object: Object{
				// 		Properties: props,
				// 	},
				// }
				fmt.Println(props)
				tmp = "any" // external struct
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
	// Add more cases to handle other types
	default:
		return ""
	}
}

func toTsTypes(t string) string {
	switch t {
	case "string":
		return "string"
	case "int", "int8", "int16", "int32", "int64", "uint", "uint8", "uint16", "uint32":
		return "number"
	case "float32", "float64":
		return "number"
	case "bool":
		return "boolean"
	case "[]byte":
		return "Uint8Array"
	default:
		return t
	}
}

func Ternary(condition bool, trueVal, falseVal string) string {
	if condition {
		return trueVal
	}
	return falseVal
}
