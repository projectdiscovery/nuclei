package utils

import (
	"encoding/binary"
)

// PackUint8 packs a uint8 value into a byte slice
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const u = new utils.Utils();
// const packed = u.PackUint8(255);
// ```
func (u *Utils) PackUint8(value int) []byte {
	return []byte{byte(value & 0xFF)}
}

// PackUint16LE packs a uint16 value into a little-endian byte slice
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const u = new utils.Utils();
// const packed = u.PackUint16LE(0x1234); // returns [0x34, 0x12]
// ```
func (u *Utils) PackUint16LE(value int) []byte {
	buf := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf, uint16(value))
	return buf
}

// PackUint16BE packs a uint16 value into a big-endian byte slice
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const u = new utils.Utils();
// const packed = u.PackUint16BE(0x1234); // returns [0x12, 0x34]
// ```
func (u *Utils) PackUint16BE(value int) []byte {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(value))
	return buf
}

// PackUint32LE packs a uint32 value into a little-endian byte slice
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const u = new utils.Utils();
// const packed = u.PackUint32LE(0x12345678); // returns [0x78, 0x56, 0x34, 0x12]
// ```
func (u *Utils) PackUint32LE(value int) []byte {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, uint32(value))
	return buf
}

// PackUint32BE packs a uint32 value into a big-endian byte slice
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const u = new utils.Utils();
// const packed = u.PackUint32BE(0x12345678); // returns [0x12, 0x34, 0x56, 0x78]
// ```
func (u *Utils) PackUint32BE(value int) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(value))
	return buf
}

// PackUint64LE packs a uint64 value into a little-endian byte slice
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const u = new utils.Utils();
// const packed = u.PackUint64LE(0x123456789ABCDEF0);
// ```
func (u *Utils) PackUint64LE(value int64) []byte {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, uint64(value))
	return buf
}

// PackUint64BE packs a uint64 value into a big-endian byte slice
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const u = new utils.Utils();
// const packed = u.PackUint64BE(0x123456789ABCDEF0);
// ```
func (u *Utils) PackUint64BE(value int64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(value))
	return buf
}

// UnpackUint16LE unpacks a little-endian uint16 from bytes at the given offset
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const u = new utils.Utils();
// const value = u.UnpackUint16LE([0x34, 0x12, 0x00, 0x00], 0); // returns 0x1234
// ```
func (u *Utils) UnpackUint16LE(data []byte, offset int) int {
	if offset+2 > len(data) {
		return 0
	}
	return int(binary.LittleEndian.Uint16(data[offset:]))
}

// UnpackUint16BE unpacks a big-endian uint16 from bytes at the given offset
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const u = new utils.Utils();
// const value = u.UnpackUint16BE([0x12, 0x34, 0x00, 0x00], 0); // returns 0x1234
// ```
func (u *Utils) UnpackUint16BE(data []byte, offset int) int {
	if offset+2 > len(data) {
		return 0
	}
	return int(binary.BigEndian.Uint16(data[offset:]))
}

// UnpackUint32LE unpacks a little-endian uint32 from bytes at the given offset
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const u = new utils.Utils();
// const value = u.UnpackUint32LE([0x78, 0x56, 0x34, 0x12], 0); // returns 0x12345678
// ```
func (u *Utils) UnpackUint32LE(data []byte, offset int) int {
	if offset+4 > len(data) {
		return 0
	}
	return int(binary.LittleEndian.Uint32(data[offset:]))
}

// UnpackUint32BE unpacks a big-endian uint32 from bytes at the given offset
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const u = new utils.Utils();
// const value = u.UnpackUint32BE([0x12, 0x34, 0x56, 0x78], 0); // returns 0x12345678
// ```
func (u *Utils) UnpackUint32BE(data []byte, offset int) int {
	if offset+4 > len(data) {
		return 0
	}
	return int(binary.BigEndian.Uint32(data[offset:]))
}

// UnpackUint64LE unpacks a little-endian uint64 from bytes at the given offset
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const u = new utils.Utils();
// const value = u.UnpackUint64LE(bytes, 0);
// ```
func (u *Utils) UnpackUint64LE(data []byte, offset int) int64 {
	if offset+8 > len(data) {
		return 0
	}
	return int64(binary.LittleEndian.Uint64(data[offset:]))
}

// UnpackUint64BE unpacks a big-endian uint64 from bytes at the given offset
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const u = new utils.Utils();
// const value = u.UnpackUint64BE(bytes, 0);
// ```
func (u *Utils) UnpackUint64BE(data []byte, offset int) int64 {
	if offset+8 > len(data) {
		return 0
	}
	return int64(binary.BigEndian.Uint64(data[offset:]))
}

// ConcatBytes concatenates multiple byte slices into one
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const u = new utils.Utils();
// const result = u.ConcatBytes([0x01, 0x02], [0x03, 0x04], [0x05]);
// ```
func (u *Utils) ConcatBytes(arrays ...[]byte) []byte {
	totalLen := 0
	for _, arr := range arrays {
		totalLen += len(arr)
	}
	result := make([]byte, 0, totalLen)
	for _, arr := range arrays {
		result = append(result, arr...)
	}
	return result
}

// StringToBytes converts a string to a byte slice
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const u = new utils.Utils();
// const bytes = u.StringToBytes('hello');
// ```
func (u *Utils) StringToBytes(s string) []byte {
	return []byte(s)
}

// BytesToString converts a byte slice to a string
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const u = new utils.Utils();
// const str = u.BytesToString([0x68, 0x65, 0x6c, 0x6c, 0x6f]);
// ```
func (u *Utils) BytesToString(data []byte) string {
	return string(data)
}

// ToBytes converts various input types to a byte slice
// Handles: []byte, []interface{} (with numeric values), string
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const u = new utils.Utils();
// const bytes = u.ToBytes([0x41, 0x42, 0x43]);
// ```
func (u *Utils) ToBytes(data interface{}) []byte {
	switch v := data.(type) {
	case []byte:
		return v
	case string:
		return []byte(v)
	case []interface{}:
		result := make([]byte, len(v))
		for i, val := range v {
			switch n := val.(type) {
			case int:
				result[i] = byte(n)
			case int64:
				result[i] = byte(n)
			case float64:
				result[i] = byte(int(n))
			default:
				result[i] = 0
			}
		}
		return result
	default:
		return nil
	}
}

// P8 packs a uint8 value (pwntools-style alias for PackUint8)
func (u *Utils) P8(value int) []byte { return u.PackUint8(value) }

// P16 packs a uint16 value as little-endian (pwntools-style alias)
func (u *Utils) P16(value int) []byte { return u.PackUint16LE(value) }

// P16BE packs a uint16 value as big-endian
func (u *Utils) P16BE(value int) []byte { return u.PackUint16BE(value) }

// P32 packs a uint32 value as little-endian (pwntools-style alias)
func (u *Utils) P32(value int) []byte { return u.PackUint32LE(value) }

// P32BE packs a uint32 value as big-endian
func (u *Utils) P32BE(value int) []byte { return u.PackUint32BE(value) }

// P64 packs a uint64 value as little-endian (pwntools-style alias)
func (u *Utils) P64(value int64) []byte { return u.PackUint64LE(value) }

// P64BE packs a uint64 value as big-endian
func (u *Utils) P64BE(value int64) []byte { return u.PackUint64BE(value) }

// U16 unpacks a little-endian uint16 (pwntools-style alias)
func (u *Utils) U16(data []byte, offset int) int { return u.UnpackUint16LE(data, offset) }

// U16BE unpacks a big-endian uint16
func (u *Utils) U16BE(data []byte, offset int) int { return u.UnpackUint16BE(data, offset) }

// U32 unpacks a little-endian uint32 (pwntools-style alias)
func (u *Utils) U32(data []byte, offset int) int { return u.UnpackUint32LE(data, offset) }

// U32BE unpacks a big-endian uint32
func (u *Utils) U32BE(data []byte, offset int) int { return u.UnpackUint32BE(data, offset) }

// U64 unpacks a little-endian uint64 (pwntools-style alias)
func (u *Utils) U64(data []byte, offset int) int64 { return u.UnpackUint64LE(data, offset) }

// U64BE unpacks a big-endian uint64
func (u *Utils) U64BE(data []byte, offset int) int64 { return u.UnpackUint64BE(data, offset) }

// Flat combines multiple items into a single byte slice
// Accepts: []byte, string, int (single byte), []interface{}, or any Pack result
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const u = new utils.Utils();
// const payload = u.Flat(u.P32(0x41414141), "AAAA", [0x00, 0x01], 0x42);
// ```
func (u *Utils) Flat(items ...interface{}) []byte {
	var result []byte
	for _, item := range items {
		switch v := item.(type) {
		case []byte:
			result = append(result, v...)
		case string:
			result = append(result, []byte(v)...)
		case int:
			result = append(result, byte(v))
		case int64:
			result = append(result, byte(v))
		case float64:
			result = append(result, byte(int(v)))
		case []interface{}:
			for _, elem := range v {
				switch n := elem.(type) {
				case int:
					result = append(result, byte(n))
				case int64:
					result = append(result, byte(n))
				case float64:
					result = append(result, byte(int(n)))
				}
			}
		}
	}
	return result
}
