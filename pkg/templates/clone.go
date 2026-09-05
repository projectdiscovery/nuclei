package templates

import (
	"reflect"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/variables"
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
	visited := newCloneVisited()
	cloned := cloneTemplateValue(reflect.ValueOf(template), visited)
	clonedTemplate := cloned.Interface().(*Template)
	clonedTemplate.Variables = cloneTemplateVariables(template.Variables, visited)
	return clonedTemplate
}

// newCloneVisited tracks values already cloned during one clone operation.
// Callers cloning several fields of the same owner must share it so values
// aliased across those fields stay aliased in the copy.
func newCloneVisited() map[cloneVisit]reflect.Value {
	return make(map[cloneVisit]reflect.Value)
}

// cloneTemplateVariables deep-copies variables, whose backing map is held in
// unexported fields that cloneTemplateValue copies by reference.
func cloneTemplateVariables(src variables.Variable, visited map[cloneVisit]reflect.Value) variables.Variable {
	dst := variables.Variable{LazyEval: src.LazyEval}
	dst.InsertionOrderedStringMap = *utils.NewEmptyInsertionOrderedStringMap(src.Len())
	src.ForEach(func(key string, value interface{}) {
		clonedValue := cloneTemplateValue(reflect.ValueOf(value), visited)
		if clonedValue.IsValid() {
			dst.Set(key, clonedValue.Interface())
		} else {
			dst.Set(key, nil)
		}
	})
	return dst
}

func cloneTemplateConstants(src map[string]interface{}, visited map[cloneVisit]reflect.Value) map[string]interface{} {
	if src == nil {
		return nil
	}
	cloned := cloneTemplateValue(reflect.ValueOf(src), visited)
	return cloned.Interface().(map[string]interface{})
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
