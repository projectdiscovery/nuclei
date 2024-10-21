package dataformat

import (
	mapsutil "github.com/projectdiscovery/utils/maps"
	"golang.org/x/exp/maps"
)

// KV is a key-value struct
// that is implemented or used by fuzzing package
// to represent a key-value pair
// sometimes order or key-value pair is important (query params)
// so we use ordered map to represent the data
// if it's not important/significant (ex: json,xml) we use map
// this also allows us to iteratively implement ordered map
type KV struct {
	Map        mapsutil.Map[string, any]
	OrderedMap *mapsutil.OrderedMap[string, any]
}

// Clones the current state of the KV struct
func (kv *KV) Clone() KV {
	newKV := KV{}
	if kv.OrderedMap == nil {
		newKV.Map = maps.Clone(kv.Map)
		return newKV
	}
	clonedOrderedMap := kv.OrderedMap.Clone()
	newKV.OrderedMap = &clonedOrderedMap
	return newKV
}

// IsNIL returns true if the KV struct is nil
func (kv *KV) IsNIL() bool {
	return kv.Map == nil && kv.OrderedMap == nil
}

// IsOrderedMap returns true if the KV struct is an ordered map
func (kv *KV) IsOrderedMap() bool {
	return kv.OrderedMap != nil
}

// Set sets a value in the KV struct
func (kv *KV) Set(key string, value any) {
	if kv.OrderedMap != nil {
		kv.OrderedMap.Set(key, value)
		return
	}
	if kv.Map == nil {
		kv.Map = make(map[string]interface{})
	}
	kv.Map[key] = value
}

// Get gets a value from the KV struct
func (kv *KV) Get(key string) interface{} {
	if kv.OrderedMap != nil {
		value, ok := kv.OrderedMap.Get(key)
		if !ok {
			return nil
		}
		return value
	}
	return kv.Map[key]
}

// Iterate iterates over the KV struct in insertion order
func (kv *KV) Iterate(f func(key string, value any) bool) {
	if kv.OrderedMap != nil {
		kv.OrderedMap.Iterate(func(key string, value any) bool {
			return f(key, value)
		})
		return
	}
	for key, value := range kv.Map {
		if !f(key, value) {
			break
		}
	}
}

// Delete deletes a key from the KV struct
func (kv *KV) Delete(key string) bool {
	if kv.OrderedMap != nil {
		_, ok := kv.OrderedMap.Get(key)
		if !ok {
			return false
		}
		kv.OrderedMap.Delete(key)
		return true
	}
	_, ok := kv.Map[key]
	if !ok {
		return false
	}
	delete(kv.Map, key)
	return true
}

// KVMap returns a new KV struct with the given map
func KVMap(data map[string]interface{}) KV {
	return KV{Map: data}
}

// KVOrderedMap returns a new KV struct with the given ordered map
func KVOrderedMap(data *mapsutil.OrderedMap[string, any]) KV {
	return KV{OrderedMap: data}
}

// ToMap converts the ordered map to a map
func ToMap(m *mapsutil.OrderedMap[string, any]) map[string]interface{} {
	data := make(map[string]interface{})
	m.Iterate(func(key string, value any) bool {
		data[key] = value
		return true
	})
	return data
}

// ToOrderedMap converts the map to an ordered map
func ToOrderedMap(data map[string]interface{}) *mapsutil.OrderedMap[string, any] {
	m := mapsutil.NewOrderedMap[string, any]()
	for key, value := range data {
		m.Set(key, value)
	}
	return &m
}
