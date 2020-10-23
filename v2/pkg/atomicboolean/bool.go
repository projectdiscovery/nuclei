package atomicboolean

import (
	"sync"
)

type AtomBool struct {
	sync.RWMutex
	flag bool
}

func New() *AtomBool {
	return &AtomBool{}
}

func (b *AtomBool) Or(value bool) {
	b.Lock()
	defer b.Unlock()

	b.flag = b.flag || value
}

func (b *AtomBool) And(value bool) {
	b.Lock()
	defer b.Unlock()

	b.flag = b.flag && value
}

func (b *AtomBool) Set(value bool) {
	b.Lock()
	defer b.Unlock()

	b.flag = value
}

func (b *AtomBool) Get() bool {
	b.RLock()
	defer b.RUnlock() //nolint

	return b.flag
}
