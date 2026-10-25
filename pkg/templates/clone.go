package templates

import (
	"reflect"

	"github.com/projectdiscovery/nuclei/v3/pkg/utils"
)

type cloneVisit struct {
	typeOf   reflect.Type
	pointer  uintptr
	length   int
	capacity int
}

// cloneTemplate copies a clean parsed template before protocol compilation
// adds engine-local state. Unexported fields hold immutable parse state at this
// point and are copied by value; exported maps, slices, pointers, and
// interfaces are copied recursively.
func cloneTemplate(template *Template) *Template {
	visited := make(map[cloneVisit]reflect.Value)
	cloned := cloneTemplateValue(reflect.ValueOf(template), visited)
	clonedTemplate := cloned.Interface().(*Template)
	clonedTemplate.Variables.InsertionOrderedStringMap = *utils.NewEmptyInsertionOrderedStringMap(template.Variables.Len())
	template.Variables.ForEach(func(key string, value interface{}) {
		clonedValue := cloneTemplateValue(reflect.ValueOf(value), visited)
		if clonedValue.IsValid() {
			clonedTemplate.Variables.Set(key, clonedValue.Interface())
		} else {
			clonedTemplate.Variables.Set(key, nil)
		}
	})
	return clonedTemplate
}

func cloneTemplateValue(value reflect.Value, visited map[cloneVisit]reflect.Value) reflect.Value {
	if !value.IsValid() {
		return value
	}

	switch value.Kind() {
	case reflect.Interface:
		if value.IsNil() {
			return reflect.Zero(value.Type())
		}
		cloned := cloneTemplateValue(value.Elem(), visited)
		result := reflect.New(value.Type()).Elem()
		result.Set(cloned)
		return result
	case reflect.Pointer:
		if value.IsNil() {
			return reflect.Zero(value.Type())
		}
		visit := cloneVisit{typeOf: value.Type(), pointer: value.Pointer()}
		if cloned, ok := visited[visit]; ok {
			return cloned
		}
		cloned := reflect.New(value.Type().Elem())
		visited[visit] = cloned
		cloned.Elem().Set(cloneTemplateValue(value.Elem(), visited))
		return cloned
	case reflect.Struct:
		cloned := reflect.New(value.Type()).Elem()
		cloned.Set(value)
		for i := 0; i < value.NumField(); i++ {
			if value.Type().Field(i).IsExported() {
				cloned.Field(i).Set(cloneTemplateValue(value.Field(i), visited))
			}
		}
		return cloned
	case reflect.Slice:
		if value.IsNil() {
			return reflect.Zero(value.Type())
		}
		visit := cloneVisit{
			typeOf:   value.Type(),
			pointer:  value.Pointer(),
			length:   value.Len(),
			capacity: value.Cap(),
		}
		if cloned, ok := visited[visit]; ok {
			return cloned
		}
		cloned := reflect.MakeSlice(value.Type(), value.Len(), value.Len())
		visited[visit] = cloned
		for i := 0; i < value.Len(); i++ {
			cloned.Index(i).Set(cloneTemplateValue(value.Index(i), visited))
		}
		return cloned
	case reflect.Map:
		if value.IsNil() {
			return reflect.Zero(value.Type())
		}
		visit := cloneVisit{typeOf: value.Type(), pointer: value.Pointer()}
		if cloned, ok := visited[visit]; ok {
			return cloned
		}
		cloned := reflect.MakeMapWithSize(value.Type(), value.Len())
		visited[visit] = cloned
		iterator := value.MapRange()
		for iterator.Next() {
			key := cloneTemplateValue(iterator.Key(), visited)
			item := cloneTemplateValue(iterator.Value(), visited)
			cloned.SetMapIndex(key, item)
		}
		return cloned
	case reflect.Array:
		cloned := reflect.New(value.Type()).Elem()
		for i := 0; i < value.Len(); i++ {
			cloned.Index(i).Set(cloneTemplateValue(value.Index(i), visited))
		}
		return cloned
	default:
		return value
	}
}
