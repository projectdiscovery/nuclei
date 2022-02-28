package utils

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
