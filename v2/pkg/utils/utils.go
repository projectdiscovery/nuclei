package utils

import (
	"reflect"
	"strings"
)

func isEmpty(value interface{}) bool {
	if value == nil {
		return true
	}

	reflectValue := reflect.ValueOf(value)
	actualValueInterface := reflectValue.Interface()

	switch reflect.TypeOf(value).Kind() {
	case reflect.String:
		reflectedValue := actualValueInterface.(string)
		return strings.TrimSpace(reflectedValue) == ""
	case reflect.Slice, reflect.Array:
		return reflectValue.Len() == 0
	case reflect.Int32:
		return IsEmpty(string(actualValueInterface.(rune)))
	default:
		if reflectValue.IsZero() {
			return true
		}
		return false
	}
}

func IsEmpty(value ...interface{}) bool {
	for _, current := range value {
		if IsNotEmpty(current) {
			return false
		}
	}
	return true
}

func IsNotEmpty(value interface{}) bool {
	return !isEmpty(value)
}
