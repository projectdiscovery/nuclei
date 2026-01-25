package utils

import (
	"bytes"
	"errors"
)

// PKCS7Pad pads data to the specified block size using PKCS7 padding
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const padded = utils.PKCS7Pad([0x41, 0x42, 0x43], 16);
// ```
func (u *Utils) PKCS7Pad(data []byte, blockSize int) []byte {
	return pkcs7Pad(data, blockSize)
}

// PKCS7Unpad removes PKCS7 padding from data
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const unpadded = utils.PKCS7Unpad(padded);
// ```
func (u *Utils) PKCS7Unpad(data []byte) ([]byte, error) {
	return pkcs7Unpad(data)
}

// ZeroPad pads data with zeros to the specified length
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const padded = utils.ZeroPad([0x41, 0x42], 8);
// ```
func (u *Utils) ZeroPad(data []byte, length int) []byte {
	if len(data) >= length {
		return data
	}
	result := make([]byte, length)
	copy(result, data)
	return result
}

// NullPad pads data with null bytes to the specified length
// (same as ZeroPad, provided for clarity)
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const padded = utils.NullPad([0x41, 0x42], 8);
// ```
func (u *Utils) NullPad(data []byte, length int) []byte {
	return u.ZeroPad(data, length)
}

// PadToBlockSize pads data to be a multiple of blockSize using zero padding
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const padded = utils.PadToBlockSize([0x41, 0x42, 0x43], 8);
// ```
func (u *Utils) PadToBlockSize(data []byte, blockSize int) []byte {
	if blockSize <= 0 {
		return data
	}
	remainder := len(data) % blockSize
	if remainder == 0 {
		return data
	}
	padding := blockSize - remainder
	return append(data, bytes.Repeat([]byte{0}, padding)...)
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("data is empty")
	}
	padding := int(data[len(data)-1])
	if padding == 0 || padding > len(data) {
		return nil, errors.New("invalid padding")
	}
	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, errors.New("invalid padding")
		}
	}
	return data[:len(data)-padding], nil
}
