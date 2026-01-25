package utils

import (
	"encoding/base64"
	"encoding/hex"
	"html"
	"net/url"
	"unicode/utf16"
)

// URLEncode URL encodes a string
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const encoded = utils.URLEncode('hello world');
// ```
func (u *Utils) URLEncode(data string) string {
	return url.QueryEscape(data)
}

// URLDecode URL decodes a string
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const decoded = utils.URLDecode('hello%20world');
// ```
func (u *Utils) URLDecode(data string) (string, error) {
	return url.QueryUnescape(data)
}

// HTMLEncode HTML encodes a string
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const encoded = utils.HTMLEncode('<script>alert(1)</script>');
// ```
func (u *Utils) HTMLEncode(data string) string {
	return html.EscapeString(data)
}

// HTMLDecode HTML decodes a string
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const decoded = utils.HTMLDecode('&lt;script&gt;');
// ```
func (u *Utils) HTMLDecode(data string) string {
	return html.UnescapeString(data)
}

// HexEncode encodes bytes to hex string
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const hex = utils.HexEncode([0x48, 0x65, 0x6c, 0x6c, 0x6f]);
// ```
func (u *Utils) HexEncode(data []byte) string {
	return hex.EncodeToString(data)
}

// HexDecode decodes hex string to bytes
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const bytes = utils.HexDecode('48656c6c6f');
// ```
func (u *Utils) HexDecode(data string) ([]byte, error) {
	return hex.DecodeString(data)
}

// Base64Encode encodes bytes to base64 string (standard encoding)
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const encoded = utils.Base64Encode([0x48, 0x65, 0x6c, 0x6c, 0x6f]);
// ```
func (u *Utils) Base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// Base64Decode decodes base64 string to bytes (standard encoding)
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const bytes = utils.Base64Decode('SGVsbG8=');
// ```
func (u *Utils) Base64Decode(data string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(data)
}

// Base64URLEncode encodes bytes to URL-safe base64 string
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const encoded = utils.Base64URLEncode([0x48, 0x65, 0x6c, 0x6c, 0x6f]);
// ```
func (u *Utils) Base64URLEncode(data []byte) string {
	return base64.URLEncoding.EncodeToString(data)
}

// Base64URLDecode decodes URL-safe base64 string to bytes
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const bytes = utils.Base64URLDecode('SGVsbG8');
// ```
func (u *Utils) Base64URLDecode(data string) ([]byte, error) {
	return base64.URLEncoding.DecodeString(data)
}

// Base64RawEncode encodes bytes to base64 string without padding
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const encoded = utils.Base64RawEncode([0x48, 0x65, 0x6c, 0x6c, 0x6f]);
// ```
func (u *Utils) Base64RawEncode(data []byte) string {
	return base64.RawStdEncoding.EncodeToString(data)
}

// Base64RawDecode decodes base64 string without padding to bytes
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const bytes = utils.Base64RawDecode('SGVsbG8');
// ```
func (u *Utils) Base64RawDecode(data string) ([]byte, error) {
	return base64.RawStdEncoding.DecodeString(data)
}

// Base64RawURLEncode encodes bytes to URL-safe base64 string without padding
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const encoded = utils.Base64RawURLEncode([0x48, 0x65, 0x6c, 0x6c, 0x6f]);
// ```
func (u *Utils) Base64RawURLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// Base64RawURLDecode decodes URL-safe base64 string without padding to bytes
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const bytes = utils.Base64RawURLDecode('SGVsbG8');
// ```
func (u *Utils) Base64RawURLDecode(data string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(data)
}

// UTF16LEEncode encodes a string to UTF-16 Little Endian bytes
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const encoded = utils.UTF16LEEncode('hello');
// ```
func (u *Utils) UTF16LEEncode(data string) []byte {
	runes := []rune(data)
	u16 := utf16.Encode(runes)
	result := make([]byte, len(u16)*2)
	for i, r := range u16 {
		result[i*2] = byte(r)
		result[i*2+1] = byte(r >> 8)
	}
	return result
}

// UTF16LEDecode decodes UTF-16 Little Endian bytes to a string
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const decoded = utils.UTF16LEDecode([0x68, 0x00, 0x65, 0x00]);
// ```
func (u *Utils) UTF16LEDecode(data []byte) string {
	if len(data)%2 != 0 {
		data = append(data, 0)
	}
	u16 := make([]uint16, len(data)/2)
	for i := 0; i < len(u16); i++ {
		u16[i] = uint16(data[i*2]) | uint16(data[i*2+1])<<8
	}
	return string(utf16.Decode(u16))
}

// UTF16BEEncode encodes a string to UTF-16 Big Endian bytes
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const encoded = utils.UTF16BEEncode('hello');
// ```
func (u *Utils) UTF16BEEncode(data string) []byte {
	runes := []rune(data)
	u16 := utf16.Encode(runes)
	result := make([]byte, len(u16)*2)
	for i, r := range u16 {
		result[i*2] = byte(r >> 8)
		result[i*2+1] = byte(r)
	}
	return result
}

// UTF16BEDecode decodes UTF-16 Big Endian bytes to a string
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const decoded = utils.UTF16BEDecode([0x00, 0x68, 0x00, 0x65]);
// ```
func (u *Utils) UTF16BEDecode(data []byte) string {
	if len(data)%2 != 0 {
		data = append(data, 0)
	}
	u16 := make([]uint16, len(data)/2)
	for i := 0; i < len(u16); i++ {
		u16[i] = uint16(data[i*2])<<8 | uint16(data[i*2+1])
	}
	return string(utf16.Decode(u16))
}
