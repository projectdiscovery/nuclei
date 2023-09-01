package buffer

import (
	"encoding/hex"

	"github.com/dop251/goja"
)

// Module is the module for working with buffers in nuclei js integration.
type Module struct{}

// TODO:
// https://github.com/dop251/goja/issues/379
// This looks like it could be used instead of this custom buffer
// implementation. However, it's not clear how to use it.
//
// Also see how k6 does it.
func (m *Module) Enable(runtime *goja.Runtime) {
	runtime.Set("bytes", map[string]interface{}{
		"Buffer": NewBuffer,
	})
}

// Buffer is a minimal buffer implementation over a byte slice
// that is used to pack/unpack binary data in nuclei js integration.
type Buffer struct {
	buf []byte
}

// NewBuffer creates a new buffer from a byte slice.
func NewBuffer(call goja.ConstructorCall) interface{} {
	obj := &Buffer{}

	obj.buf = make([]byte, 0)
	return map[string]interface{}{
		"append":  obj.Append,
		"bytes":   obj.Bytes,
		"string":  obj.String,
		"len":     obj.Len,
		"hex":     obj.Hex,
		"hexdump": obj.Hexdump,
	}
}

// Append appends a byte slice to the buffer.
func (b *Buffer) Append(data []byte) *Buffer {
	b.buf = append(b.buf, data...)
	return b
}

// Bytes returns the byte slice of the buffer.
func (b *Buffer) Bytes() []byte {
	return b.buf
}

// String returns the string representation of the buffer.
func (b *Buffer) String() string {
	return string(b.buf)
}

// Len returns the length of the buffer.
func (b *Buffer) Len() int {
	return len(b.buf)
}

// Hex returns the hex representation of the buffer.
func (b *Buffer) Hex() string {
	return hex.EncodeToString(b.buf)
}

// Hexdump returns the hexdump representation of the buffer.
func (b *Buffer) Hexdump() string {
	return hex.Dump(b.buf)
}
