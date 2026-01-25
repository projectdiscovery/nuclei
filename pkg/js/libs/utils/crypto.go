package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rc4"
	"errors"
)

// AESEncryptECB encrypts data using AES in ECB mode
// Key must be 16, 24, or 32 bytes for AES-128, AES-192, AES-256
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const key = Rand(16);
// const encrypted = utils.AESEncryptECB(ToBytes('plaintext'), key);
// ```
func (u *Utils) AESEncryptECB(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plaintext = pkcs7Pad(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i += aes.BlockSize {
		block.Encrypt(ciphertext[i:], plaintext[i:])
	}
	return ciphertext, nil
}

// AESDecryptECB decrypts data using AES in ECB mode
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const decrypted = utils.AESDecryptECB(encrypted, key);
// ```
func (u *Utils) AESDecryptECB(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}
	plaintext := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i += aes.BlockSize {
		block.Decrypt(plaintext[i:], ciphertext[i:])
	}
	return pkcs7Unpad(plaintext)
}

// AESEncryptCBC encrypts data using AES in CBC mode
// Key must be 16, 24, or 32 bytes. IV must be 16 bytes.
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const key = Rand(16);
// const iv = Rand(16);
// const encrypted = utils.AESEncryptCBC(ToBytes('plaintext'), key, iv);
// ```
func (u *Utils) AESEncryptCBC(plaintext, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != aes.BlockSize {
		return nil, errors.New("IV must be 16 bytes")
	}
	plaintext = pkcs7Pad(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)
	return ciphertext, nil
}

// AESDecryptCBC decrypts data using AES in CBC mode
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const decrypted = utils.AESDecryptCBC(encrypted, key, iv);
// ```
func (u *Utils) AESDecryptCBC(ciphertext, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != aes.BlockSize {
		return nil, errors.New("IV must be 16 bytes")
	}
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}
	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)
	return pkcs7Unpad(plaintext)
}

// AESEncryptGCM encrypts data using AES in GCM mode
// Key must be 16, 24, or 32 bytes. Nonce should be 12 bytes.
// Returns ciphertext with authentication tag appended.
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const key = Rand(16);
// const nonce = Rand(12);
// const encrypted = utils.AESEncryptGCM(ToBytes('plaintext'), key, nonce);
// ```
func (u *Utils) AESEncryptGCM(plaintext, key, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nil
}

// AESDecryptGCM decrypts data using AES in GCM mode
// Expects ciphertext with authentication tag appended.
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const decrypted = utils.AESDecryptGCM(encrypted, key, nonce);
// ```
func (u *Utils) AESDecryptGCM(ciphertext, key, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// DESEncryptECB encrypts data using DES in ECB mode
// Key must be 8 bytes
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const key = Rand(8);
// const encrypted = utils.DESEncryptECB(ToBytes('plaintext'), key);
// ```
func (u *Utils) DESEncryptECB(plaintext, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plaintext = pkcs7Pad(plaintext, des.BlockSize)
	ciphertext := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i += des.BlockSize {
		block.Encrypt(ciphertext[i:], plaintext[i:])
	}
	return ciphertext, nil
}

// DESDecryptECB decrypts data using DES in ECB mode
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const decrypted = utils.DESDecryptECB(encrypted, key);
// ```
func (u *Utils) DESDecryptECB(ciphertext, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext)%des.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}
	plaintext := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i += des.BlockSize {
		block.Decrypt(plaintext[i:], ciphertext[i:])
	}
	return pkcs7Unpad(plaintext)
}

// DES3EncryptCBC encrypts data using Triple DES in CBC mode
// Key must be 24 bytes. IV must be 8 bytes.
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const key = Rand(24);
// const iv = Rand(8);
// const encrypted = utils.DES3EncryptCBC(ToBytes('plaintext'), key, iv);
// ```
func (u *Utils) DES3EncryptCBC(plaintext, key, iv []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != des.BlockSize {
		return nil, errors.New("IV must be 8 bytes")
	}
	plaintext = pkcs7Pad(plaintext, des.BlockSize)
	ciphertext := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)
	return ciphertext, nil
}

// DES3DecryptCBC decrypts data using Triple DES in CBC mode
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const decrypted = utils.DES3DecryptCBC(encrypted, key, iv);
// ```
func (u *Utils) DES3DecryptCBC(ciphertext, key, iv []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != des.BlockSize {
		return nil, errors.New("IV must be 8 bytes")
	}
	if len(ciphertext)%des.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}
	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)
	return pkcs7Unpad(plaintext)
}

// RC4Encrypt encrypts/decrypts data using RC4 (symmetric)
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const key = Rand(16);
// const encrypted = utils.RC4Encrypt(ToBytes('plaintext'), key);
// const decrypted = utils.RC4Encrypt(encrypted, key); // RC4 is symmetric
// ```
func (u *Utils) RC4Encrypt(data, key []byte) ([]byte, error) {
	c, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	result := make([]byte, len(data))
	c.XORKeyStream(result, data)
	return result, nil
}

// XORBytes XORs data with a repeating key
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const xored = utils.XORBytes([0x41, 0x42, 0x43], [0x01, 0x02]);
// ```
func (u *Utils) XORBytes(data, key []byte) []byte {
	if len(key) == 0 {
		return data
	}
	result := make([]byte, len(data))
	for i := range data {
		result[i] = data[i] ^ key[i%len(key)]
	}
	return result
}

// XORSingleByte XORs each byte of data with a single byte key
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const xored = utils.XORSingleByte([0x41, 0x42, 0x43], 0x01);
// ```
func (u *Utils) XORSingleByte(data []byte, key byte) []byte {
	result := make([]byte, len(data))
	for i := range data {
		result[i] = data[i] ^ key
	}
	return result
}
