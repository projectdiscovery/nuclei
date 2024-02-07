package tsgen

import (
	"fmt"
	"go/types"
	"regexp"
	"strings"

	errorutil "github.com/projectdiscovery/utils/errors"
)

// scrape.go scrapes all information of exported type from different package

func (p *EntityParser) scrapeAndCreate(typeName string) error {
	if p.newObjects[typeName] == nil {
		return nil
	}
	// get package name
	pkgName := strings.Split(typeName, ".")[0]
	baseTypeName := strings.Split(typeName, ".")[1]
	// get package
	pkg, ok := p.imports[pkgName]
	if !ok {
		return errorutil.New("package %v for type %v not found", pkgName, typeName)
	}
	// get type
	obj := pkg.Types.Scope().Lookup(baseTypeName)
	if obj == nil {
		return errorutil.New("type %v not found in package %+v", typeName, pkg)
	}
	// Ensure the object is a type name
	typeNameObj, ok := obj.(*types.TypeName)
	if !ok {
		return errorutil.New("%v is not a type name", typeName)
	}
	// Ensure the type is a named struct type
	namedStruct, ok := typeNameObj.Type().Underlying().(*types.Struct)
	if !ok {
		return fmt.Errorf("%s is not a named struct type", typeName)
	}
	// fmt.Printf("got named struct %v\n", namedStruct)
	// Iterate over the struct fields
	d := &ExtObject{
		builtIn: make(map[string]string),
		nested:  map[string]map[string]*ExtObject{},
	}

	// fmt.Printf("fields %v\n", namedStruct.NumFields())
	for i := 0; i < namedStruct.NumFields(); i++ {
		field := namedStruct.Field(i)
		fieldName := field.Name()
		if field.Exported() {
			recursiveScrapeType(nil, fieldName, field.Type(), d)
		}
	}
	entityMap := make(map[string]Entity)
	// convert ExtObject to Entity
	properties := ConvertExtObjectToEntities(d, entityMap)
	entityMap[baseTypeName] = Entity{
		Name:        baseTypeName,
		Type:        "interface",
		Description: fmt.Sprintf("%v Interface", baseTypeName),
		Object: Interface{
			Properties: properties,
		},
	}

	for _, entity := range entityMap {
		p.entities = append(p.entities, entity)
	}

	return nil
}

type ExtObject struct {
	builtIn map[string]string
	nested  map[string]map[string]*ExtObject // Changed to map of field names to ExtObject
}

func recursiveScrapeType(parentType types.Type, fieldName string, fieldType types.Type, extObject *ExtObject) {
	if named, ok := fieldType.(*types.Named); ok && !named.Obj().Exported() {
		// fmt.Printf("type %v is not exported\n", named.Obj().Name())
		return
	}

	if fieldType.String() == "time.Time" {
		extObject.builtIn[fieldName] = "Date"
		return
	}

	switch t := fieldType.Underlying().(type) {
	case *types.Pointer:
		// fmt.Printf("type %v is a pointer\n", fieldType)
		recursiveScrapeType(nil, fieldName, t.Elem(), extObject)
	case *types.Signature:
		// fmt.Printf("type %v is a callback or interface\n", fieldType)
	case *types.Basic:
		// Check for basic types (built-in types)
		if parentType != nil {
			switch p := parentType.Underlying().(type) {
			case *types.Slice:
				extObject.builtIn[fieldName] = "[]" + fieldType.String()
			case *types.Array:
				extObject.builtIn[fieldName] = fmt.Sprintf("[%v]", p.Len()) + fieldType.String()
			}
		} else {
			extObject.builtIn[fieldName] = fieldType.String()
		}
	case *types.Struct:
		// Check for struct types
		if extObject.nested[fieldName] == nil {
			// @tarunKoyalwar: it currently does not supported struct arrays
			extObject.nested[fieldName] = make(map[string]*ExtObject)
		}
		nestedExtObject := &ExtObject{
			builtIn: make(map[string]string),
			nested:  map[string]map[string]*ExtObject{},
		}
		extObject.nested[fieldName][fieldType.String()] = nestedExtObject
		for i := 0; i < t.NumFields(); i++ {
			field := t.Field(i)
			if field.Exported() {
				recursiveScrapeType(nil, field.Name(), field.Type(), nestedExtObject)
			}
		}
	case *types.Array:
		// fmt.Printf("type %v is an array\n", fieldType)
		// get array type
		recursiveScrapeType(t, fieldName, t.Elem(), extObject)
	case *types.Slice:
		// fmt.Printf("type %v is a slice\n", fieldType)
		// get slice type
		recursiveScrapeType(t, fieldName, t.Elem(), extObject)
	default:
		// fmt.Printf("type %v is not a builtIn or struct\n", fieldType)
	}
}

var re = regexp.MustCompile(`\[[0-9]+\].*`)

// ConvertExtObjectToEntities recursively converts an ExtObject to a list of Entity objects
func ConvertExtObjectToEntities(extObj *ExtObject, nestedTypes map[string]Entity) []Property {
	var properties []Property

	// Iterate over the built-in types
	for fieldName, fieldType := range extObj.builtIn {
		var description string
		if re.MatchString(fieldType) {
			// if it is a fixed size array add len in description
			description = fmt.Sprintf("fixed size array of length: %v", fieldType[:strings.Index(fieldType, "]")+1])
			// remove length from type
			fieldType = "[]" + fieldType[strings.Index(fieldType, "]")+1:]
		}
		if strings.Contains(fieldType, "time.Duration") {
			description = "time in nanoseconds"
		}
		px := Property{
			Name:        fieldName,
			Type:        toTsTypes(fieldType),
			Description: description,
		}

		if strings.HasPrefix(px.Type, "[") {
			px.Type = fieldType[strings.Index(px.Type, "]")+1:] + "[]"
		}
		properties = append(properties, px)
	}

	// Iterate over the nested types
	for fieldName, nestedExtObjects := range extObj.nested {
		for origType, nestedExtObject := range nestedExtObjects {
			// fix:me this nestedExtObject always has only one element
			got := ConvertExtObjectToEntities(nestedExtObject, nestedTypes)
			baseTypename := origType[strings.LastIndex(origType, ".")+1:]
			// create new nestedType
			nestedTypes[baseTypename] = Entity{
				Name:        baseTypename,
				Description: fmt.Sprintf("%v Interface", baseTypename),
				Type:        "interface",
				Object: Interface{
					Properties: got,
				},
			}
			// assign current field type to nested type
			properties = append(properties, Property{
				Name: fieldName,
				Type: baseTypename,
			})
		}
	}
	return properties
}
