package main

import (
	"errors"
	"fmt"
	"go/ast"
	"go/types"
	"strings"

	"golang.org/x/tools/go/packages"
)

func pkgMap(node *ast.File) map[string]*packages.Package {
	// get all import statements
	imports := node.Imports
	// create a map to store the package path and the package
	pkgMap := make(map[string]*packages.Package)
	// iterate over all imports
	for _, imp := range imports {
		// get the package path
		path := imp.Path.Value
		// remove the quotes from the path
		path = path[1 : len(path)-1]
		// load the package
		pkg, err := loadPackage(path)
		if err != nil {
			panic(err)
		}
		// add the package to the map
		pkgMap[path[strings.LastIndex(path, "/")+1:]] = pkg
	}
	return pkgMap
}

// Load the package containing the type definition
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

// Find and extract the fields from the specified type
func extractFieldsFromType(pkg *packages.Package, typeName string) ([]Property, error) {
	var properties []Property

	// Find the type within the package's type information
	obj := pkg.Types.Scope().Lookup(typeName)
	if obj == nil {
		return nil, fmt.Errorf("type %s not found in package %+v", typeName, pkg)
	}

	// Ensure the object is a type name
	typeNameObj, ok := obj.(*types.TypeName)
	if !ok {
		return nil, fmt.Errorf("%s is not a type name", typeName)
	}

	// Ensure the type is a named struct type
	namedStruct, ok := typeNameObj.Type().Underlying().(*types.Struct)
	if !ok {
		return nil, fmt.Errorf("%s is not a named struct type", typeName)
	}

	// Iterate over the struct fields
	for i := 0; i < namedStruct.NumFields(); i++ {
		field := namedStruct.Field(i)

		// Check if the field is exported
		if field.Exported() {
			fieldType := field.Type()

			// Check if the field's type is a built-in type or a struct
			if isBuiltinOrStruct(fieldType) {
				properties = append(properties, Property{
					Name: field.Name(),
					Type: fieldType.String(), // You may need to process this to get the TypeScript type
				})
			}
		}
	}

	return properties, nil
}

// Check if the type is a built-in type or a struct
func isBuiltinOrStruct(t types.Type) bool {
	// Check for basic types (built-in types)
	if _, ok := t.(*types.Basic); ok {
		return true
	}

	// Check for struct types
	if _, ok := t.Underlying().(*types.Struct); ok {
		return true
	}

	// Add more checks if necessary for other types you want to include

	return false
}

// func main() {
// 	// Load the package that contains the type definition
// 	pkg, err := loadPackage("path/to/your/package")
// 	if err != nil {
// 		log.Fatalf("Error loading package: %v", err)
// 	}

// 	// Extract the fields from the type
// 	properties, err := extractFieldsFromType(pkg, "ssh.SomeType")
// 	if err != nil {
// 		log.Fatalf("Error extracting fields: %v", err)
// 	}

// 	// Output the properties (this is where you would generate your @Object)
// 	for _, prop := range properties {
// 		fmt.Printf("Field: %s, Type: %s\n", prop.Name, prop.Type)
// 	}
// }
