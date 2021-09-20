// Package kb implements a knowledgebase system for Nuclei Scanner.
package kb

import (
	"sync"
)

var Global = New()

// Knowledgebase is a shared kb used by nuclei engine internally
// during request-making/sharing target data.
//
// The knowledgebase stores key-value pairs where keys are template-id:target-hash:name.
// Values are a slice and can be set multiple times for the same key.
// The engine will automatically append the values while making sure to only add
// unique items to the values.
type Knowledgebase struct {
	items map[string]*kbKey
	mutex *sync.RWMutex
}

// New returns a new knowledgebase structure
func New() *Knowledgebase {
	return &Knowledgebase{items: make(map[string]*kbKey), mutex: &sync.RWMutex{}}
}

// Set sets a key with a value to the knowledgebase.
func (k *Knowledgebase) Set(host, key, value string) {
	k.mutex.RLock()
	kbKey, ok := k.items[key]
	k.mutex.RUnlock()

	if !ok {
		kbKey := newKBKey()
		kbKey.Set(host, value)

		k.mutex.Lock()
		k.items[key] = kbKey
		k.mutex.Unlock()
		return
	}
	kbKey.Set(host, value)
}

// Get returns the values for a key.
//
// If the key was not found, the defaultValue specified as second
// argument to the Get function is returned.
//
// The key is template-id:name specified in the template.
// This function appends the host the key is asked for as well before the loookup.
func (k *Knowledgebase) Get(host, key string) []string {
	k.mutex.RLock()
	kbKey, ok := k.items[key]
	k.mutex.RUnlock()

	if !ok {
		return nil
	}
	values := kbKey.Get(host)
	return values
}

// Delete deletes a key after it has been processed for all hosts.
func (k *Knowledgebase) Delete(key string) {
	k.mutex.Lock()
	delete(k.items, key)
	k.mutex.Unlock()
}

// kbKey is a key in templateid-name format stored in the knowledgebase.
type kbKey struct {
	hosts map[string][]string
	mutex *sync.RWMutex
}

func newKBKey() *kbKey {
	return &kbKey{hosts: make(map[string][]string), mutex: &sync.RWMutex{}}
}

func (k *kbKey) Get(host string) []string {
	k.mutex.RLock()
	values, ok := k.hosts[host]
	k.mutex.RUnlock()
	if !ok {
		return nil
	}
	return values
}

func (k *kbKey) Set(host, value string) {
	k.mutex.Lock()
	defer k.mutex.Unlock()

	values, ok := k.hosts[host]
	if !ok {
		k.hosts[host] = []string{value}
		return
	}
	k.hosts[host] = append(values, value)
}
