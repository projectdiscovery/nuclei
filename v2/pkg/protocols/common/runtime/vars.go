package runtime

type Store struct {
	kv map[string]interface{}
}

func New() (*Store, error) {
	return &Store{kv: map[string]interface{}{}}, nil
}

func (store *Store) Reset() {
	for k := range store.kv {
		// removes var references
		delete(store.kv, k)
	}
}

func (store *Store) Set(key string, value interface{}) {
	store.kv[key] = value
}

func (store *Store) Get(key string) interface{} {
	v, ok := store.kv[key]
	if ok {
		return v
	}
	return nil
}

func (store *Store) Has(key string) bool {
	_, ok := store.kv[key]
	return ok
}

func (store *Store) Del(key string) {
	delete(store.kv, key)
}

func (store *Store) Len() int {
	return len(store.kv)
}
