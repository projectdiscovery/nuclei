package utils

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash/adler32"
	"hash/crc32"

	"golang.org/x/crypto/md4"
)

// MD4 computes MD4 hash of data (needed for NTLM)
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const hash = utils.MD4('password');
// ```
func (u *Utils) MD4(data []byte) string {
	h := md4.New()
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// MD4Raw computes MD4 hash of data and returns raw bytes
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const hash = utils.MD4Raw('password');
// ```
func (u *Utils) MD4Raw(data []byte) []byte {
	h := md4.New()
	h.Write(data)
	return h.Sum(nil)
}

// MD5 computes MD5 hash of data
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const hash = utils.MD5('password');
// ```
func (u *Utils) MD5(data []byte) string {
	h := md5.Sum(data)
	return hex.EncodeToString(h[:])
}

// MD5Raw computes MD5 hash of data and returns raw bytes
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const hash = utils.MD5Raw('password');
// ```
func (u *Utils) MD5Raw(data []byte) []byte {
	h := md5.Sum(data)
	return h[:]
}

// SHA1 computes SHA1 hash of data
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const hash = utils.SHA1('password');
// ```
func (u *Utils) SHA1(data []byte) string {
	h := sha1.Sum(data)
	return hex.EncodeToString(h[:])
}

// SHA1Raw computes SHA1 hash of data and returns raw bytes
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const hash = utils.SHA1Raw('password');
// ```
func (u *Utils) SHA1Raw(data []byte) []byte {
	h := sha1.Sum(data)
	return h[:]
}

// SHA256 computes SHA256 hash of data
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const hash = utils.SHA256('password');
// ```
func (u *Utils) SHA256(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// SHA256Raw computes SHA256 hash of data and returns raw bytes
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const hash = utils.SHA256Raw('password');
// ```
func (u *Utils) SHA256Raw(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// SHA384 computes SHA384 hash of data
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const hash = utils.SHA384('password');
// ```
func (u *Utils) SHA384(data []byte) string {
	h := sha512.Sum384(data)
	return hex.EncodeToString(h[:])
}

// SHA384Raw computes SHA384 hash of data and returns raw bytes
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const hash = utils.SHA384Raw('password');
// ```
func (u *Utils) SHA384Raw(data []byte) []byte {
	h := sha512.Sum384(data)
	return h[:]
}

// SHA512 computes SHA512 hash of data
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const hash = utils.SHA512('password');
// ```
func (u *Utils) SHA512(data []byte) string {
	h := sha512.Sum512(data)
	return hex.EncodeToString(h[:])
}

// SHA512Raw computes SHA512 hash of data and returns raw bytes
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const hash = utils.SHA512Raw('password');
// ```
func (u *Utils) SHA512Raw(data []byte) []byte {
	h := sha512.Sum512(data)
	return h[:]
}

// HMACMD5 computes HMAC-MD5 of data with key
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const hmac = utils.HMACMD5('message', 'key');
// ```
func (u *Utils) HMACMD5(data, key []byte) []byte {
	h := hmac.New(md5.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// HMACSHA1 computes HMAC-SHA1 of data with key
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const hmac = utils.HMACSHA1('message', 'key');
// ```
func (u *Utils) HMACSHA1(data, key []byte) []byte {
	h := hmac.New(sha1.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// HMACSHA256 computes HMAC-SHA256 of data with key
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const hmac = utils.HMACSHA256('message', 'key');
// ```
func (u *Utils) HMACSHA256(data, key []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// HMACSHA512 computes HMAC-SHA512 of data with key
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const hmac = utils.HMACSHA512('message', 'key');
// ```
func (u *Utils) HMACSHA512(data, key []byte) []byte {
	h := hmac.New(sha512.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// CRC32 computes CRC32 checksum of data
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const checksum = utils.CRC32('data');
// ```
func (u *Utils) CRC32(data []byte) uint32 {
	return crc32.ChecksumIEEE(data)
}

// Adler32 computes Adler32 checksum of data
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const checksum = utils.Adler32('data');
// ```
func (u *Utils) Adler32(data []byte) uint32 {
	return adler32.Checksum(data)
}
