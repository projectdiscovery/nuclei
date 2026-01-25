package utils

import (
	"bytes"
	"math/rand"
	"strings"
)

const patternCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
const alphanumCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// PatternCreate creates a cyclic pattern of specified length for buffer overflow analysis
// The pattern is designed to have unique 4-byte sequences for easy offset identification
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const pattern = utils.PatternCreate(1000);
// ```
func (u *Utils) PatternCreate(length int) []byte {
	if length <= 0 {
		return []byte{}
	}
	pattern := make([]byte, length)
	idx := 0
	for i := 0; i < 26 && idx < length; i++ {
		for j := 0; j < 26 && idx < length; j++ {
			for k := 0; k < 10 && idx < length; k++ {
				pattern[idx] = byte('A' + i)
				idx++
				if idx < length {
					pattern[idx] = byte('a' + j)
					idx++
				}
				if idx < length {
					pattern[idx] = byte('0' + k)
					idx++
				}
			}
		}
	}
	return pattern
}

// PatternOffset finds the offset of a 4-byte pattern within a cyclic pattern
// Returns -1 if pattern is not found
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const pattern = utils.PatternCreate(1000);
// const offset = utils.PatternOffset(pattern, ToBytes('Aa0A'));
// ```
func (u *Utils) PatternOffset(pattern, search []byte) int {
	return bytes.Index(pattern, search)
}

// FindBytes finds the first occurrence of needle in haystack
// Returns -1 if not found
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const idx = utils.FindBytes([0x41, 0x42, 0x43, 0x44], [0x42, 0x43]);
// ```
func (u *Utils) FindBytes(haystack, needle []byte) int {
	return bytes.Index(haystack, needle)
}

// FindAllBytes finds all occurrences of needle in haystack
// Returns array of indices
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const indices = utils.FindAllBytes([0x41, 0x42, 0x41, 0x42], [0x41, 0x42]);
// ```
func (u *Utils) FindAllBytes(haystack, needle []byte) []int {
	var indices []int
	start := 0
	for {
		idx := bytes.Index(haystack[start:], needle)
		if idx == -1 {
			break
		}
		indices = append(indices, start+idx)
		start += idx + 1
	}
	return indices
}

// ReplaceBytes replaces all occurrences of old with new in data
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const result = utils.ReplaceBytes([0x41, 0x42, 0x43], [0x42], [0x44, 0x45]);
// ```
func (u *Utils) ReplaceBytes(data, old, new []byte) []byte {
	return bytes.ReplaceAll(data, old, new)
}

// RepeatBytes repeats data count times
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const repeated = utils.RepeatBytes([0x41, 0x42], 3);
// ```
func (u *Utils) RepeatBytes(data []byte, count int) []byte {
	return bytes.Repeat(data, count)
}

// ReverseBytes reverses a byte slice
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const reversed = utils.ReverseBytes([0x41, 0x42, 0x43]);
// ```
func (u *Utils) ReverseBytes(data []byte) []byte {
	result := make([]byte, len(data))
	for i, j := 0, len(data)-1; j >= 0; i, j = i+1, j-1 {
		result[i] = data[j]
	}
	return result
}

// SwapEndian16 swaps endianness of 16-bit values in data
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const swapped = utils.SwapEndian16([0x01, 0x02, 0x03, 0x04]);
// ```
func (u *Utils) SwapEndian16(data []byte) []byte {
	result := make([]byte, len(data))
	copy(result, data)
	for i := 0; i+1 < len(result); i += 2 {
		result[i], result[i+1] = result[i+1], result[i]
	}
	return result
}

// SwapEndian32 swaps endianness of 32-bit values in data
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const swapped = utils.SwapEndian32([0x01, 0x02, 0x03, 0x04]);
// ```
func (u *Utils) SwapEndian32(data []byte) []byte {
	result := make([]byte, len(data))
	copy(result, data)
	for i := 0; i+3 < len(result); i += 4 {
		result[i], result[i+1], result[i+2], result[i+3] = result[i+3], result[i+2], result[i+1], result[i]
	}
	return result
}

// GenerateRandomString generates a random string of specified length
// using alphanumeric characters
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const str = utils.GenerateRandomString(16);
// ```
func (u *Utils) GenerateRandomString(length int) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = alphanumCharset[rand.Intn(len(alphanumCharset))]
	}
	return string(b)
}

// GenerateRandomAlphanumeric generates a random alphanumeric string
// (alias for GenerateRandomString)
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const str = utils.GenerateRandomAlphanumeric(16);
// ```
func (u *Utils) GenerateRandomAlphanumeric(length int) string {
	return u.GenerateRandomString(length)
}

// GenerateRandomBytes generates random bytes of specified length
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const bytes = utils.GenerateRandomBytes(16);
// ```
func (u *Utils) GenerateRandomBytes(length int) []byte {
	b := make([]byte, length)
	for i := range b {
		b[i] = byte(rand.Intn(256))
	}
	return b
}

// RepeatString repeats a string count times
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const repeated = utils.RepeatString('A', 100);
// ```
func (u *Utils) RepeatString(s string, count int) string {
	return strings.Repeat(s, count)
}

// PadLeft pads string on the left to specified length
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const padded = utils.PadLeft('123', 8, '0');
// ```
func (u *Utils) PadLeft(s string, length int, pad string) string {
	if len(s) >= length {
		return s
	}
	if pad == "" {
		pad = " "
	}
	for len(s) < length {
		s = pad + s
	}
	return s[len(s)-length:]
}

// PadRight pads string on the right to specified length
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const padded = utils.PadRight('123', 8, '0');
// ```
func (u *Utils) PadRight(s string, length int, pad string) string {
	if len(s) >= length {
		return s
	}
	if pad == "" {
		pad = " "
	}
	for len(s) < length {
		s = s + pad
	}
	return s[:length]
}
