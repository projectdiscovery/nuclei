package bytes

import (
	"encoding/hex"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/libs/structs"
)

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
		"Write":       obj.Write,
		"WriteString": obj.WriteString,
		"Pack":        obj.Pack,
		"Bytes":       obj.Bytes,
		"String":      obj.String,
		"Len":         obj.Len,
		"Hex":         obj.Hex,
		"Hexdump":     obj.Hexdump,
	}
}

// Write appends a byte slice to the buffer.
func (b *Buffer) Write(data []byte) *Buffer {
	b.buf = append(b.buf, data...)
	return b
}

// WriteString appends a string to the buffer.
func (b *Buffer) WriteString(data string) *Buffer {
	b.buf = append(b.buf, []byte(data)...)
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

// Pack uses structs.Pack and packs given data and appends it to the buffer.
// it packs the data according to the given format.
func (b *Buffer) Pack(formatStr string, msg []interface{}) error {
	bin, err := structs.Pack(formatStr, msg)
	if err != nil {
		return err
	}
	b.Write(bin)
	return nil
}
