package utils

import (
	"fmt"
	"strconv"

	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/yaml"
)

type InsertionOrderedStringMap struct {
	keys   []string `yaml:"-"`
	values map[string]interface{}
}

func NewEmptyInsertionOrderedStringMap(size int) *InsertionOrderedStringMap {
	return &InsertionOrderedStringMap{
		keys:   make([]string, 0, size),
		values: make(map[string]interface{}, size),
	}
}

func NewInsertionOrderedStringMap(stringMap map[string]interface{}) *InsertionOrderedStringMap {
	result := NewEmptyInsertionOrderedStringMap(len(stringMap))

	for k, v := range stringMap {
		result.Set(k, v)
	}
	return result
}

func (insertionOrderedStringMap *InsertionOrderedStringMap) Len() int {
	return len(insertionOrderedStringMap.values)
}

func (insertionOrderedStringMap *InsertionOrderedStringMap) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var data yaml.MapSlice
	if err := unmarshal(&data); err != nil {
		return err
	}
	insertionOrderedStringMap.values = make(map[string]interface{})
	for _, v := range data {
		if v.Key == nil {
			continue
		}
		// Only string keys are valid here. A bare `1:` or `true:` key decodes to a
		// non-string value, which previously panicked; reject it with an error
		// instead of converting, so `1` and "1" are never merged into one entry.
		key, ok := v.Key.(string)
		if !ok {
			return fmt.Errorf("invalid map key %v (%T): keys must be strings, quote the key to use it as a string", v.Key, v.Key)
		}
		insertionOrderedStringMap.Set(key, toString(v.Value))
	}
	return nil
}

func (insertionOrderedStringMap *InsertionOrderedStringMap) UnmarshalJSON(data []byte) error {
	var dataMap map[string]interface{}
	if err := json.Unmarshal(data, &dataMap); err != nil {
		return err
	}
	insertionOrderedStringMap.values = make(map[string]interface{})
	for k, v := range dataMap {
		insertionOrderedStringMap.Set(k, toString(v))
	}
	return nil
}

// toString converts an interface to string in a quick way
func toString(data interface{}) interface{} {
	switch s := data.(type) {
	case nil:
		return ""
	case string:
		return s
	case bool:
		return strconv.FormatBool(s)
	case float64:
		return strconv.FormatFloat(s, 'f', -1, 64)
	case float32:
		return strconv.FormatFloat(float64(s), 'f', -1, 32)
	case int:
		return strconv.Itoa(s)
	case int64:
		return strconv.FormatInt(s, 10)
	case int32:
		return strconv.Itoa(int(s))
	case int16:
		return strconv.FormatInt(int64(s), 10)
	case int8:
		return strconv.FormatInt(int64(s), 10)
	case uint:
		return strconv.FormatUint(uint64(s), 10)
	case uint64:
		return strconv.FormatUint(s, 10)
	case uint32:
		return strconv.FormatUint(uint64(s), 10)
	case uint16:
		return strconv.FormatUint(uint64(s), 10)
	case uint8:
		return strconv.FormatUint(uint64(s), 10)
	case []byte:
		return string(s)
	case []interface{}:
		return data
	default:
		return fmt.Sprintf("%v", data)
	}
}

func (insertionOrderedStringMap *InsertionOrderedStringMap) ForEach(fn func(key string, data interface{})) {
	for _, key := range insertionOrderedStringMap.keys {
		fn(key, insertionOrderedStringMap.values[key])
	}
}

func (insertionOrderedStringMap *InsertionOrderedStringMap) Set(key string, value interface{}) {
	_, present := insertionOrderedStringMap.values[key]
	insertionOrderedStringMap.values[key] = value
	if !present {
		insertionOrderedStringMap.keys = append(insertionOrderedStringMap.keys, key)
	}
}
