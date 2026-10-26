package types

import (
	"io"
	"reflect"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog"
)

// Copy must carry every exported option. Fields added later without a matching
// line in Copy are silently dropped wherever options are copied (for example in
// every execution of the SDK's thread-safe engine). This test sets each
// exported field to a non-zero value and checks it survives Copy.
func TestCopyKeepsEveryExportedField(t *testing.T) {
	src := &Options{}
	v := reflect.ValueOf(src).Elem()
	typ := v.Type()
	var skipped []string
	for i := 0; i < v.NumField(); i++ {
		f := typ.Field(i)
		if !f.IsExported() {
			continue
		}
		if !fillNonZero(v.Field(i)) {
			skipped = append(skipped, f.Name)
		}
	}
	got := reflect.ValueOf(src.Copy()).Elem()
	for i := 0; i < v.NumField(); i++ {
		f := typ.Field(i)
		if !f.IsExported() || contains(skipped, f.Name) {
			continue
		}
		if !reflect.DeepEqual(v.Field(i).Interface(), got.Field(i).Interface()) {
			t.Errorf("Copy drops %s", f.Name)
		}
	}
	if len(skipped) > 0 {
		t.Logf("not checked (kind cannot be filled generically): %v", skipped)
	}
}

// fillNonZero cannot fill an interface or a func, so check those two directly.
func TestCopyKeepsParserAndLoadHelperFileFunction(t *testing.T) {
	parser := &struct{}{}
	loader := LoadHelperFileFunction(func(string, string, catalog.Catalog) (io.ReadCloser, error) {
		return nil, nil
	})
	src := &Options{
		Parser:                 parser,
		LoadHelperFileFunction: loader,
	}

	got := src.Copy()
	if got.Parser != parser {
		t.Fatal("Copy drops Parser")
	}
	if got.LoadHelperFileFunction == nil {
		t.Fatal("Copy drops LoadHelperFileFunction")
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// fillNonZero sets v to a non-zero value and reports whether it could.
func fillNonZero(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(7)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(7)
	case reflect.Float32, reflect.Float64:
		v.SetFloat(7)
	case reflect.String:
		v.SetString("x")
	case reflect.Slice:
		s := reflect.MakeSlice(v.Type(), 1, 1)
		fillNonZero(s.Index(0))
		v.Set(s)
	case reflect.Map:
		v.Set(reflect.MakeMap(v.Type()))
		v.SetMapIndex(reflect.New(v.Type().Key()).Elem(), reflect.New(v.Type().Elem()).Elem())
	case reflect.Pointer:
		v.Set(reflect.New(v.Type().Elem()))
	case reflect.Struct:
		filled := false
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).IsExported() && fillNonZero(v.Field(i)) {
				filled = true
			}
		}
		return filled
	default:
		return false
	}
	return true
}
