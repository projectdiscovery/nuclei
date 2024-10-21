package bytes

import (
	"encoding/hex"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/libs/structs"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/utils"
)

type (
	// Buffer is a bytes/Uint8Array type in javascript
	// @example
	// ```javascript
	// const bytes = require('nuclei/bytes');
	// const bytes = new bytes.Buffer();
	// ```
	// @example
	// ```javascript
	// const bytes = require('nuclei/bytes');
	// // optionally it can accept existing byte/Uint8Array as input
	// const bytes = new bytes.Buffer([1, 2, 3]);
	// ```
	Buffer struct {
		buf []byte
	}
)

// NewBuffer creates a new buffer from a byte slice.
func NewBuffer(call goja.ConstructorCall, runtime *goja.Runtime) *goja.Object {
	if len(call.Arguments) > 0 {
		if arg, ok := call.Argument(0).Export().([]byte); ok {
			return utils.LinkConstructor(call, runtime, &Buffer{buf: arg})
		} else {
			utils.NewNucleiJS(runtime).Throw("Invalid argument type. Expected bytes/Uint8Array as input but got %T", call.Argument(0).Export())
		}
	}
	return utils.LinkConstructor(call, runtime, &Buffer{})
}

// Write appends the given data to the buffer.
// @example
// ```javascript
// const bytes = require('nuclei/bytes');
// const buffer = new bytes.Buffer();
// buffer.Write([1, 2, 3]);
// ```
func (b *Buffer) Write(data []byte) *Buffer {
	b.buf = append(b.buf, data...)
	return b
}

// WriteString appends the given string data to the buffer.
// @example
// ```javascript
// const bytes = require('nuclei/bytes');
// const buffer = new bytes.Buffer();
// buffer.WriteString('hello');
// ```
func (b *Buffer) WriteString(data string) *Buffer {
	b.buf = append(b.buf, []byte(data)...)
	return b
}

// Bytes returns the byte representation of the buffer.
// @example
// ```javascript
// const bytes = require('nuclei/bytes');
// const buffer = new bytes.Buffer();
// buffer.WriteString('hello');
// log(buffer.Bytes());
// ```
func (b *Buffer) Bytes() []byte {
	return b.buf
}

// String returns the string representation of the buffer.
// @example
// ```javascript
// const bytes = require('nuclei/bytes');
// const buffer = new bytes.Buffer();
// buffer.WriteString('hello');
// log(buffer.String());
// ```
func (b *Buffer) String() string {
	return string(b.buf)
}

// Len returns the length of the buffer.
// @example
// ```javascript
// const bytes = require('nuclei/bytes');
// const buffer = new bytes.Buffer();
// buffer.WriteString('hello');
// log(buffer.Len());
// ```
func (b *Buffer) Len() int {
	return len(b.buf)
}

// Hex returns the hex representation of the buffer.
// @example
// ```javascript
// const bytes = require('nuclei/bytes');
// const buffer = new bytes.Buffer();
// buffer.WriteString('hello');
// log(buffer.Hex());
// ```
func (b *Buffer) Hex() string {
	return hex.EncodeToString(b.buf)
}

// Hexdump returns the hexdump representation of the buffer.
// @example
// ```javascript
// const bytes = require('nuclei/bytes');
// const buffer = new bytes.Buffer();
// buffer.WriteString('hello');
// log(buffer.Hexdump());
// ```
func (b *Buffer) Hexdump() string {
	return hex.Dump(b.buf)
}

// Pack uses structs.Pack and packs given data and appends it to the buffer.
// it packs the data according to the given format.
// @example
// ```javascript
// const bytes = require('nuclei/bytes');
// const buffer = new bytes.Buffer();
// buffer.Pack('I', 123);
// ```
func (b *Buffer) Pack(formatStr string, msg any) error {
	bin, err := structs.Pack(formatStr, msg)
	if err != nil {
		return err
	}
	b.Write(bin)
	return nil
}
