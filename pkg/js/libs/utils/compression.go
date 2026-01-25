package utils

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"io"
)

// ZlibCompress compresses data using zlib
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const compressed = utils.ZlibCompress('hello world');
// ```
func (u *Utils) ZlibCompress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	_, err := w.Write(data)
	if err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ZlibDecompress decompresses zlib compressed data
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const decompressed = utils.ZlibDecompress(compressed);
// ```
func (u *Utils) ZlibDecompress(data []byte) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

// GzipCompress compresses data using gzip
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const compressed = utils.GzipCompress('hello world');
// ```
func (u *Utils) GzipCompress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, err := w.Write(data)
	if err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// GzipDecompress decompresses gzip compressed data
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const decompressed = utils.GzipDecompress(compressed);
// ```
func (u *Utils) GzipDecompress(data []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

// DeflateCompress compresses data using raw deflate (no zlib header)
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const compressed = utils.DeflateCompress('hello world');
// ```
func (u *Utils) DeflateCompress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		return nil, err
	}
	_, err = w.Write(data)
	if err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DeflateDecompress decompresses raw deflate compressed data
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const decompressed = utils.DeflateDecompress(compressed);
// ```
func (u *Utils) DeflateDecompress(data []byte) ([]byte, error) {
	r := flate.NewReader(bytes.NewReader(data))
	defer r.Close()
	return io.ReadAll(r)
}
